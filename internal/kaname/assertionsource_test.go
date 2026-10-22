// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

package kaname_test

import "context"

type assertionSource func() string

func (f assertionSource) Assertion(context.Context) (string, error) { return f(), nil }
