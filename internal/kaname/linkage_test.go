// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

package kaname

import (
	"os/exec"
	"strings"
	"testing"
)

// Ответ операции kaname — google.protobuf.Any, и protojson разбирает его только
// по типу, зарегистрированному в ПРОЦЕССЕ. Удаление учётки отвечает
// google.protobuf.Empty: бинарник, не связавший emptypb, получал отказ разбора на
// каждом чтении операции удаления (замер на стенде kaname @93ad1b88), а пробы
// этого не видели — двойник в том же тестовом процессе связывал тип сам.
// Бинарник cmd связывал emptypb случайно, через стороннюю зависимость, а
// интеграционный — нет. Поэтому связность судится по графу САМОГО пакета
// клиента (не тестового процесса и не бинарника): клиент, разбирающий ответ,
// связывает его тип сам, и любой бинарник с клиентом его получает.
func TestClientPackageLinksEveryOperationResponseType(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		t.Fatalf("go list -deps .: %v", err)
	}
	deps := map[string]bool{}
	for _, p := range strings.Fields(string(out)) {
		deps[p] = true
	}
	if len(deps) < 50 {
		t.Fatalf("dependency census of the binary read %d packages: the walk did not happen", len(deps))
	}
	for _, want := range []string{
		"google.golang.org/protobuf/types/known/emptypb",             // Delete*: google.protobuf.Empty
		"github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1", // ответы и метаданные iam
		"github.com/PRO-Robotech/corelib/api/corelib/operation",      // сама операция
	} {
		if !deps[want] {
			t.Errorf("package kaname does not link %s: operation responses of that type will not decode", want)
		}
	}
}
