// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

// Package config — конфигурация оператора: файл платформы, проверяемый на
// старте. Проверка закрыта на отказ: процесс с неполной или противоречивой
// конфигурацией не стартует, а не работает в урезанном режиме.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"

	"sigs.k8s.io/yaml"
)

// Config — конфигурация оператора.
type Config struct {
	// ClusterName — имя кластера: идёт в метки владения kaname и в пути Vault.
	ClusterName string `json:"clusterName"`
	Kaname      Kaname `json:"kaname"`
	Vault       Vault  `json:"vault"`
	Policy      Policy `json:"policy"`
	// Delivery — перечень приложений доставки ключей.
	Delivery Delivery `json:"delivery"`
	Keys     Keys     `json:"keys"`
}

// Kaname — доступ к kaname IAM.
type Kaname struct {
	// APIURL — origin REST-фронта kaname (https://host[:port]).
	APIURL string `json:"apiURL"`
	// TokenURL — токен-эндпоинт; пусто — APIURL + /iam/v1/token.
	TokenURL string `json:"tokenURL,omitempty"`
	// Audience — адресат утверждения (aud), идентификатор издателя kaname.
	Audience string `json:"audience"`
	// RequestedAudience — адресат выдаваемого токена (параметр audience
	// обмена); пусто — умолчание установки kaname.
	RequestedAudience string `json:"requestedAudience,omitempty"`
	// CAFile — УЦ сервера kaname; пусто — системные корни.
	CAFile string `json:"caFile,omitempty"`
	// CallTimeout — дедлайн каждого вызова kaname.
	CallTimeout Duration `json:"callTimeout,omitempty"`
	// AssertionTTL — срок утверждения TokenRequest (≥ 10 мин, ≤ 1 ч).
	AssertionTTL Duration `json:"assertionTTL,omitempty"`
	// QPS и Burst — ограничитель темпа вызовов kaname.
	QPS   float64 `json:"qps,omitempty"`
	Burst int     `json:"burst,omitempty"`
}

// Vault — доступ к Vault.
type Vault struct {
	// Address — https://host[:port] Vault.
	Address string `json:"address"`
	// CAFile — УЦ Vault; пусто — системные корни.
	CAFile string `json:"caFile,omitempty"`
	// AuthMount — путь метода kubernetes-auth (без auth/).
	AuthMount string `json:"authMount"`
	// Role — роль kubernetes-auth.
	Role string `json:"role"`
	// TokenPath — файл projected-токена SA с адресатом Vault.
	TokenPath string `json:"tokenPath"`
	// CallTimeout — дедлайн каждого вызова Vault.
	CallTimeout Duration `json:"callTimeout,omitempty"`
}

// Policy — ограждение выдач на стороне оператора (дублирует ограждение
// допуска на случай его обхода).
type Policy struct {
	// AllowedRoles — роли, которые разрешено выдавать.
	AllowedRoles []string `json:"allowedRoles"`
	// SystemClassRoles — роли, допустимые для субъектов-системных классов.
	SystemClassRoles []string `json:"systemClassRoles,omitempty"`
	// PlatformPrincipals — пользователи k8s, чьи CR вправе называть субъектом
	// пользователя или группу kaname.
	PlatformPrincipals []string `json:"platformPrincipals,omitempty"`
	// TargetResolvers — как тип цели разрешается в объект namespace CR.
	TargetResolvers map[string]TargetResolver `json:"targetResolvers,omitempty"`
}

// TargetResolver — объект k8s, которым подтверждается цель выдачи.
type TargetResolver struct {
	Group      string `json:"group"`
	Version    string `json:"version"`
	Resource   string `json:"resource"`
	Namespaced bool   `json:"namespaced,omitempty"`
	// Match — условия на поля объекта; значение "$namespace" — namespace CR.
	Match []FieldMatch `json:"match"`
}

// FieldMatch — равенство поля объекта значению.
type FieldMatch struct {
	// Path — путь поля через точку (spec.registryRef.namespace).
	Path string `json:"path"`
	// Equals — ожидаемое строковое значение либо "$namespace".
	Equals string `json:"equals"`
}

// NamespacePlaceholder — значение FieldMatch.Equals, означающее namespace CR.
const NamespacePlaceholder = "$namespace"

// Delivery — доставка ключей.
type Delivery struct {
	// Vault — приложения доставки в Vault по имени (spec.keys[].delivery.vault.app).
	Vault map[string]VaultApp `json:"vault,omitempty"`
}

// VaultApp — куда приложение получает ключи.
type VaultApp struct {
	// Mount — mount KV v2.
	Mount string `json:"mount"`
	// PathTemplate — путь внутри mount с подстановками {cluster}, {namespace},
	// {instance}, {name}, {key}; обязательны {namespace}, {name}, {key}.
	PathTemplate string `json:"pathTemplate"`
}

// Keys — параметры протокола ключей.
type Keys struct {
	// OrphanGrace — сколько ждать, прежде чем отозвать ключ, выпущенный, но не
	// дошедший до Vault.
	OrphanGrace Duration `json:"orphanGrace,omitempty"`
}

// Duration — time.Duration в YAML строкой Go ("10s").
type Duration struct{ time.Duration }

// UnmarshalJSON читает длительность строкой Go.
func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("duration must be a string like \"10s\": %w", err)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	d.Duration = v
	return nil
}

// MarshalJSON пишет длительность строкой Go.
func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(d.String()) }

// Умолчания и пределы.
const (
	defaultKanameCallTimeout = 10 * time.Second
	defaultVaultCallTimeout  = 5 * time.Second
	maxCallTimeout           = time.Minute
	// minAssertionTTL — нижняя граница TokenRequest kube-apiserver.
	minAssertionTTL = 10 * time.Minute
	// maxAssertionTTL — потолок длительности федеративного утверждения kaname
	// (tokenpolicy.MaxFederatedAssertionLifetime).
	maxAssertionTTL      = time.Hour
	defaultAssertionTTL  = minAssertionTTL
	defaultOrphanGrace   = 10 * time.Minute
	minOrphanGrace       = time.Minute
	defaultQPS           = 10
	defaultBurst         = 20
	defaultTokenEndpoint = "/iam/v1/token"
)

var (
	dnsLabelRe     = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)
	mountRe        = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)
	placeholderRe  = regexp.MustCompile(`\{[^{}]*\}`)
	fieldPathRe    = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9]*(\.[a-zA-Z][a-zA-Z0-9]*)*$`)
	pathLiteralRe  = regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`)
	segmentValueRe = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$`)
)

// knownPlaceholders — закрытый перечень подстановок шаблона пути.
var knownPlaceholders = []string{"{cluster}", "{namespace}", "{instance}", "{name}", "{key}"}

// requiredPlaceholders — без них пути разных CR совпали бы.
var requiredPlaceholders = []string{"{namespace}", "{name}", "{key}"}

// Load читает файл конфигурации, применяет умолчания и проверяет её.
func Load(file string) (*Config, error) {
	data, err := os.ReadFile(file) //nolint:gosec // путь задаёт флаг процесса, не вход запроса.
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", file, err)
	}
	return Parse(data)
}

// Parse разбирает конфигурацию, применяет умолчания и проверяет её.
// Неизвестное поле — отказ: опечатка в ключе иначе молча оставила бы умолчание.
func Parse(data []byte) (*Config, error) {
	var c Config
	if err := yaml.UnmarshalStrict(data, &c); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	c.applyDefaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) applyDefaults() {
	if c.Kaname.CallTimeout.Duration == 0 {
		c.Kaname.CallTimeout.Duration = defaultKanameCallTimeout
	}
	if c.Kaname.AssertionTTL.Duration == 0 {
		c.Kaname.AssertionTTL.Duration = defaultAssertionTTL
	}
	if c.Kaname.TokenURL == "" && c.Kaname.APIURL != "" {
		c.Kaname.TokenURL = strings.TrimSuffix(c.Kaname.APIURL, "/") + defaultTokenEndpoint
	}
	if c.Kaname.QPS == 0 {
		c.Kaname.QPS = defaultQPS
	}
	if c.Kaname.Burst == 0 {
		c.Kaname.Burst = defaultBurst
	}
	if c.Vault.CallTimeout.Duration == 0 {
		c.Vault.CallTimeout.Duration = defaultVaultCallTimeout
	}
	if c.Keys.OrphanGrace.Duration == 0 {
		c.Keys.OrphanGrace.Duration = defaultOrphanGrace
	}
}

// Validate проверяет конфигурацию; первая же ошибка — отказ старта.
func (c *Config) Validate() error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	if !dnsLabelRe.MatchString(c.ClusterName) {
		add("clusterName %q must be a DNS label", c.ClusterName)
	}
	if err := httpsOrigin(c.Kaname.APIURL); err != nil {
		add("kaname.apiURL: %v", err)
	}
	if err := httpsURL(c.Kaname.TokenURL); err != nil {
		add("kaname.tokenURL: %v", err)
	}
	if strings.TrimSpace(c.Kaname.Audience) == "" {
		add("kaname.audience is required: it is the aud of the assertion kaname accepts")
	}
	if d := c.Kaname.CallTimeout.Duration; d <= 0 || d > maxCallTimeout {
		add("kaname.callTimeout %s must be in (0, %s]", d, maxCallTimeout)
	}
	if d := c.Kaname.AssertionTTL.Duration; d < minAssertionTTL || d > maxAssertionTTL {
		add("kaname.assertionTTL %s must be in [%s, %s]", d, minAssertionTTL, maxAssertionTTL)
	}
	if c.Kaname.QPS < 0 || c.Kaname.Burst < 1 {
		add("kaname.qps must be >= 0 and kaname.burst >= 1")
	}

	if err := httpsOrigin(c.Vault.Address); err != nil {
		add("vault.address: %v", err)
	}
	if !mountRe.MatchString(c.Vault.AuthMount) && !validMountPath(c.Vault.AuthMount) {
		add("vault.authMount %q is not a mount path", c.Vault.AuthMount)
	}
	if strings.TrimSpace(c.Vault.Role) == "" {
		add("vault.role is required")
	}
	if !path.IsAbs(c.Vault.TokenPath) {
		add("vault.tokenPath %q must be an absolute file path", c.Vault.TokenPath)
	}
	if d := c.Vault.CallTimeout.Duration; d <= 0 || d > maxCallTimeout {
		add("vault.callTimeout %s must be in (0, %s]", d, maxCallTimeout)
	}

	errs = append(errs, c.Policy.validate()...)
	errs = append(errs, c.Delivery.validate()...)

	if d := c.Keys.OrphanGrace.Duration; d < minOrphanGrace {
		add("keys.orphanGrace %s must be at least %s", d, minOrphanGrace)
	}
	if len(errs) > 0 {
		return fmt.Errorf("config: %w", errors.Join(errs...))
	}
	return nil
}

func (p *Policy) validate() []error {
	var errs []error
	if len(p.AllowedRoles) == 0 {
		errs = append(errs, errors.New("policy.allowedRoles must name at least one role"))
	}
	for _, r := range p.SystemClassRoles {
		if !slices.Contains(p.AllowedRoles, r) {
			errs = append(errs, fmt.Errorf("policy.systemClassRoles: %q is not in policy.allowedRoles", r))
		}
	}
	for typ, r := range p.TargetResolvers {
		where := fmt.Sprintf("policy.targetResolvers[%q]", typ)
		if r.Version == "" || r.Resource == "" {
			errs = append(errs, fmt.Errorf("%s: version and resource are required", where))
		}
		if len(r.Match) == 0 {
			errs = append(errs, fmt.Errorf("%s: match must have at least one condition", where))
			continue
		}
		bound := false
		for i, m := range r.Match {
			if !fieldPathRe.MatchString(m.Path) {
				errs = append(errs, fmt.Errorf("%s.match[%d]: path %q is not a dotted field path", where, i, m.Path))
			}
			if m.Equals == NamespacePlaceholder {
				bound = true
			}
		}
		if !bound && !r.Namespaced {
			errs = append(errs, fmt.Errorf("%s: a cluster-scoped resolver must bind the object to the CR namespace with equals: %s", where, NamespacePlaceholder))
		}
	}
	return errs
}

func (d *Delivery) validate() []error {
	var errs []error
	for app, v := range d.Vault {
		where := fmt.Sprintf("delivery.vault[%q]", app)
		if !dnsLabelRe.MatchString(app) {
			errs = append(errs, fmt.Errorf("%s: app name must be a DNS label", where))
		}
		if !mountRe.MatchString(v.Mount) {
			errs = append(errs, fmt.Errorf("%s: mount %q must be a single path segment", where, v.Mount))
		}
		errs = append(errs, validateTemplate(where, v.PathTemplate)...)
	}
	return errs
}

func validateTemplate(where, tpl string) []error {
	var errs []error
	if tpl == "" || strings.HasPrefix(tpl, "/") || strings.HasSuffix(tpl, "/") {
		return []error{fmt.Errorf("%s: pathTemplate %q must be a relative path without a leading or trailing slash", where, tpl)}
	}
	for _, ph := range placeholderRe.FindAllString(tpl, -1) {
		if !slices.Contains(knownPlaceholders, ph) {
			errs = append(errs, fmt.Errorf("%s: pathTemplate has unknown placeholder %s", where, ph))
		}
	}
	for _, ph := range requiredPlaceholders {
		if !strings.Contains(tpl, ph) {
			errs = append(errs, fmt.Errorf("%s: pathTemplate must contain %s", where, ph))
		}
	}
	for _, seg := range strings.Split(tpl, "/") {
		lit := placeholderRe.ReplaceAllString(seg, "x")
		if seg == "" || seg == "." || seg == ".." || !pathLiteralRe.MatchString(lit) {
			errs = append(errs, fmt.Errorf("%s: pathTemplate segment %q is not allowed", where, seg))
		}
	}
	return errs
}

// validMountPath — путь метода из нескольких сегментов (kubernetes/system-1).
func validMountPath(p string) bool {
	if p == "" || strings.HasPrefix(p, "/") || strings.HasSuffix(p, "/") {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if !mountRe.MatchString(seg) {
			return false
		}
	}
	return true
}

func httpsURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("%q must be an https URL", raw)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("%q must carry no credentials, query or fragment", raw)
	}
	return nil
}

func httpsOrigin(raw string) error {
	if err := httpsURL(raw); err != nil {
		return err
	}
	u, _ := url.Parse(raw)
	if u.Path != "" && u.Path != "/" {
		return fmt.Errorf("%q must be an origin without a path", raw)
	}
	return nil
}

// PathParams — подстановки шаблона пути Vault.
type PathParams struct {
	Namespace string
	Instance  string
	Name      string
	Key       string
}

// VaultPath вычисляет mount и путь записи ключа для приложения app. Значение
// подстановки обязано быть именем k8s без разделителя пути: путь записи
// вычисляет оператор, и вход CR не уводит его в чужой каталог.
func (c *Config) VaultPath(app string, p PathParams) (string, string, error) {
	v, ok := c.Delivery.Vault[app]
	if !ok {
		return "", "", fmt.Errorf("delivery app %q is not configured", app)
	}
	values := map[string]string{
		"{cluster}":   c.ClusterName,
		"{namespace}": p.Namespace,
		"{instance}":  p.Instance,
		"{name}":      p.Name,
		"{key}":       p.Key,
	}
	for ph, val := range values {
		if !segmentValueRe.MatchString(val) || strings.Contains(val, "..") {
			return "", "", fmt.Errorf("value %q of %s is not a path-safe name", val, ph)
		}
	}
	out := placeholderRe.ReplaceAllStringFunc(v.PathTemplate, func(ph string) string { return values[ph] })
	return v.Mount, out, nil
}
