# kaname-iam-operator

Kubernetes operator for kaname IAM. It reflects two namespaced custom resources of
`iam.kaname.in-cloud.io/v1alpha1` into kaname `/iam/v1`:

| Kind | kaname object | Notes |
|---|---|---|
| `ServiceAccount` | service account + its keys | keys are delivered to Vault KV v2; secrets never touch Kubernetes |
| `AccessBinding` | access binding | role, subjects and scope are immutable; the target is exactly one of `resources` (named objects of the CR namespace) or `allInScope: {}` (every object of the scope, including later ones); a target change creates a new binding before the old one is revoked |

The operator authenticates to kaname with a **FEDERATED** key: it asks the API server
for a fresh token of its own service account (TokenRequest, one per exchange — kaname
accepts every assertion once) and exchanges it at `POST /iam/v1/token`
(`urn:ietf:params:oauth:grant-type:jwt-bearer`). No static kaname credential exists.

## How it behaves

* **Ownership by labels.** kaname has no creator field on service accounts, so every
  object the operator creates carries `k8s.in-cloud.io/uid` (the CR uid) and
  `k8s.in-cloud.io/cluster`. An existing object with the same name/key is adopted only
  when it carries both; otherwise the CR reports `Conflict=True` and nothing is called.
* **Whole scope.** `target: {allInScope: {}}` grants the role on every object of the
  scope — the namespace's account (`scope.type: iam.account`) or project — including
  objects registered after the grant. It is a cascade, so it is accepted only from a
  platform principal under the admission guarantee (see `policy.platformPrincipals`),
  only with a role from `policy.allowedRoles` found among kaname **system** roles, and
  never for a system class subject; nothing in the namespace is resolved for it. The
  binding is adopted by its ownership labels like any other; a binding with the same
  subjects, role, scope and `allInScope` target that does not carry them is reported as
  `Conflict=True` and neither adopted nor revoked.
* **Drift is reported, never undone.** An account disabled or deleted, a key or a
  binding revoked in kaname outside the operator turns the CR `Drifted=True`,
  `Ready=False`. Recovery happens once per new value of the annotation
  `iam.kaname.in-cloud.io/resync-drift`, which only a platform principal may set.
  An account the operator disabled because of `spec.enabled: false` is recorded as such
  in `status.disabledBySpec` before the call, and `spec.enabled: true` enables it again.
* **Intent before creation.** Before creating an account or a binding the operator writes
  its intent to `status` with a resourceVersion check (the account and the time; for a
  binding also its fingerprint). An object created whose id never reached `status` is
  found again by its ownership labels: adopted on the next pass, revoked or deleted when
  the CR is deleted (the account is taken from `status`, else from the namespace
  annotation), and a binding owned by the CR but not the one it holds is revoked before a
  new one is created. kaname creates the object in the background after answering the
  call, so until the creation is confirmed — by its operation or by the object showing
  up — an empty lookup is not taken as proof of absence: for `kaname.createGrace`
  (default 10m) from the intent the CR keeps its finalizer and no second binding is
  created. A creation still unconfirmed after the window is reported as a
  `CreateUnconfirmed` warning event.
* **Key protocol.** Before issuing, the intent (nonce, time) is written to `status` with
  a resourceVersion check; the nonce goes into the key labels in kaname and into the
  Vault record; the Vault record is written with check-and-set. A crash between any two
  steps is recognised by the nonce: a Vault record with our nonce finishes the issuance,
  a kaname key with our nonce but no record (secret lost) is replaced after
  `keys.orphanGrace` and revoked. Rotation keeps the previous key for the overlap window.
  The Vault record carries its owner (`ownerUid`, `cluster`, `keyName`) in the same
  check-and-set write; a record at the key path with another owner is neither
  overwritten nor deleted, and the key reports `Conflict=True` (`NotOwned`).
* **Policy is judged on every pass.** A binding the operator policy no longer permits —
  `policy.allowedRoles` or `policy.platformPrincipals` narrowed, the admission guarantee
  lost — is revoked in kaname the way deletion revokes it (replaced, current, own by
  labels, the unconfirmed-create window), whatever its `deletionPolicy`, and is not
  granted again while the policy forbids it: the CR reports `Rejected=True`
  (`PolicyNarrowed`). A binding that stays permissible is untouched; once permitted
  again, it is granted anew. A configuration change restarts the operator pod (config
  checksum), so every CR is judged by the new policy.
* **Deletion.** `AccessBinding`: the binding is revoked. `ServiceAccount`: waits until
  no `AccessBinding` refers to it, disables the account, revokes every key, deletes the
  Vault records, deletes the account. `deletionPolicy: Orphan` removes the finalizer only.
* **One mutation per pass.** Every reconcile pass performs at most one mutating kaname
  call; a running operation is recorded in `status.pendingOperation` and polled.
* **Errors.** kaname refusals are classified by a closed table: retryable
  (`UNAVAILABLE`, `DEADLINE_EXCEEDED`, `RESOURCE_EXHAUSTED`, `INTERNAL`,
  `FAILED_PRECONDITION`, `ABORTED`) back off 2 s → 5 min; `INVALID_ARGUMENT` waits for a
  spec change (re-checked every 10 min); `PERMISSION_DENIED`/`UNAUTHENTICATED` report
  `Forbidden`; anything else is retried with its text. There is no "unknown means success".

## Configuration

The operator reads `/etc/kaname-iam-operator/config.yaml` (chart value `config`) and
refuses to start on an incomplete or contradictory file. Notable keys:

| Key | Meaning |
|---|---|
| `clusterName` | ownership label value and `{cluster}` in Vault paths |
| `kaname.apiURL`, `kaname.tokenURL` | REST front origin and token endpoint (https only) |
| `kaname.audience` | `aud` of the assertion — the kaname issuer identifier |
| `kaname.requestedAudience` | `audience` of the exchange — the REST front audience |
| `vault.*` | Vault address, kubernetes-auth mount and role, projected token path |
| `policy.allowedRoles`, `systemClassRoles` | operator-side check, independent of admission; a role is looked up among **system** roles only — a tenant role of the same name is never granted |
| `policy.platformPrincipals`, `policy.admissionGuard` | who may name user and group subjects and set an `allInScope` target; the author is read from `created-by`, which only admission makes authentic, so user and group subjects and `allInScope` are accepted only while every policy in `admissionGuard` (and its binding of the same name) is installed, denies, is not narrowed and stood when the current spec was written: the policy predates the CR, or the operator saw the same policy object (uid, `status.admissionWitness`) at an earlier spec generation. A spec written while a policy was absent is refused until the next spec change under the reinstalled, already seen policy. The chart fills `admissionGuard` when `admission.enabled` with its writers, bindings and status policies — the status policy keeps `status.admissionWitness` written by the operator alone; without admission they are refused |
| `policy.targetResolvers` | how a target type resolves to an object of the CR namespace |
| `delivery.vault.<app>` | KV v2 mount and path template (`{cluster}`, `{namespace}`, `{instance}`, `{name}`, `{key}`); `{cluster}`, `{namespace}`, `{name}`, `{key}` are required and every placeholder is a whole path segment, so two keys never share a path |

Tenant namespaces carry `iam.kaname.in-cloud.io/account-id` and
`iam.kaname.in-cloud.io/project-id`; the CR never names an account or project itself.

## Platform prerequisites

1. A kaname service account for the operator with a FEDERATED key:
   `trusted_subjects{issuer: <cluster SA issuer>, subject_pattern:
   ^system:serviceaccount:<ns>:kaname-iam-operator$, public_key_pem: <cluster SA signing key>,
   key_algorithm}`. kaname accepts only a public https issuer.
2. Grants for that account: `editor` on each tenant account and `admin` on each tenant
   project (authority to grant); account-scoped bindings, `allInScope` on an account
   among them, need `admin` on the account. Listing bindings by account must be allowed — the
   operator adopts its bindings through `GET /iam/v1/accounts/{id}/accessBindings`.
3. A Vault role bound to the operator's service account with create/read/update/delete
   on the delivery paths only.

## Admission

The chart installs three `ValidatingAdmissionPolicy` objects:

* **writers** — only `admission.writers` (and `writerGroups`) create, change or delete
  the CRs; the namespace controller and the garbage collector may delete; the operator
  may change finalizers only. The `resync-drift` annotation is set only by a platform
  principal; `created-by`, when present, must name the creating user and is immutable.
* **bindings** — role from `policy.allowedRoles`; system class subjects only with
  `systemClassRoles`; user and group subjects and an `allInScope` target only from
  `platformPrincipals`. These rules judge the grant, so they apply on create and on a
  spec change; an update that leaves the spec intact (the operator's finalizers) is
  judged by the writers policy alone.
* **status** — `/status` is written only by the operator and `admission.statusWriters`.

The writers list is configurable so that a delivery controller (for example the
Argo CD application controller) can own the CRs.

## Development

```
make build            # manager binary
make test             # unit, envtest controller suites, CRD schema and admission suites
make lint             # golangci-lint v2 (all build tags)
make test-integration # against a kaname stand (KIO_STAND_* env) and a Vault container
make test-e2e         # kind: image, chart install, rollout, leader, admission
make docker-build IMG=prorobotech/kaname-iam-operator:dev
```

`make test` prints the number of executed tests and fails when none ran, a test was
skipped or a package failed before its tests. The kaname client is checked against a
double built on kaname's generated gateway handlers; the same contract probe runs
against a real kaname in `make test-integration`.
