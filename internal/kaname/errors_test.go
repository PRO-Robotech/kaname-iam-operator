// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

package kaname

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"testing"

	"google.golang.org/grpc/codes"
)

// TestClassifyCoversEveryCode — классификация закрыта: у каждого кода gRPC
// названа реакция, и ни один код не отнесён к «успеху».
func TestClassifyCoversEveryCode(t *testing.T) {
	want := map[codes.Code]Class{
		codes.Canceled:           ClassUnknown,
		codes.Unknown:            ClassUnknown,
		codes.InvalidArgument:    ClassInvalid,
		codes.DeadlineExceeded:   ClassRetryable,
		codes.NotFound:           ClassNotFound,
		codes.AlreadyExists:      ClassAlreadyExists,
		codes.PermissionDenied:   ClassForbidden,
		codes.ResourceExhausted:  ClassRetryable,
		codes.FailedPrecondition: ClassRetryable,
		codes.Aborted:            ClassRetryable,
		codes.OutOfRange:         ClassInvalid,
		codes.Unimplemented:      ClassUnknown,
		codes.Internal:           ClassRetryable,
		codes.Unavailable:        ClassRetryable,
		codes.DataLoss:           ClassUnknown,
		codes.Unauthenticated:    ClassForbidden,
	}
	for c := codes.Code(1); c <= codes.Unauthenticated; c++ {
		w, ok := want[c]
		if !ok {
			t.Fatalf("code %s has no declared class in the test table", c)
		}
		err := fmt.Errorf("wrapped: %w", &Error{Op: "X", Code: c, Message: "m"})
		if got := Classify(err); got != w {
			t.Errorf("Classify(%s) = %s, want %s", c, got, w)
		}
		if got := CodeOf(err); got != c {
			t.Errorf("CodeOf(%s) = %s", c, got)
		}
	}
}

func TestClassifyTransportFailures(t *testing.T) {
	if got := Classify(nil); got != ClassNone {
		t.Errorf("Classify(nil) = %s, want None", got)
	}
	if got := Classify(context.DeadlineExceeded); got != ClassRetryable {
		t.Errorf("deadline = %s, want Retryable", got)
	}
	netErr := &url.Error{Op: "Get", URL: "https://k", Err: &net.OpError{Op: "dial", Err: errors.New("connection refused")}}
	if got := Classify(netErr); got != ClassRetryable {
		t.Errorf("dial failure = %s, want Retryable", got)
	}
	// Законный близнец: ошибка не транспорта и не kaname — не «повторяемая
	// по умолчанию», а неизвестная, с текстом.
	if got := Classify(errors.New("decode: unexpected token")); got != ClassUnknown {
		t.Errorf("plain error = %s, want Unknown", got)
	}
	if got := CodeOf(errors.New("x")); got != codes.Unknown {
		t.Errorf("CodeOf(plain) = %s", got)
	}
}
