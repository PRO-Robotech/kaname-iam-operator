// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

package kaname

import (
	"context"
	"errors"
	"fmt"
	"net"

	"google.golang.org/grpc/codes"
)

// Error — отказ kaname: код gRPC (из тела ответа края либо выведенный из
// статуса HTTP), статус HTTP и текст отказа.
type Error struct {
	// Op — вызов, получивший отказ (например "ServiceAccounts.Get").
	Op string
	// Code — код gRPC отказа.
	Code codes.Code
	// HTTPStatus — статус HTTP ответа; 0 — отказ операции, а не вызова.
	HTTPStatus int
	// Message — текст отказа kaname.
	Message string
}

func (e *Error) Error() string {
	return fmt.Sprintf("kaname %s: %s: %s", e.Op, e.Code, e.Message)
}

// Class — что делать оператору с отказом. Закрытый перечень: корзины
// «прочее — успех» нет, неизвестное — повтор с текстом отказа.
type Class int

const (
	// ClassNone — отказа нет.
	ClassNone Class = iota
	// ClassRetryable — временный отказ: повтор с нарастающей паузой.
	ClassRetryable
	// ClassInvalid — kaname отверг вход: повтор только на смену spec.
	ClassInvalid
	// ClassForbidden — у оператора нет права либо входа: долгая пауза, событие.
	ClassForbidden
	// ClassNotFound — объекта нет.
	ClassNotFound
	// ClassAlreadyExists — объект уже есть: путь усыновления.
	ClassAlreadyExists
	// ClassUnknown — неизвестный отказ: повтор с текстом.
	ClassUnknown
)

func (c Class) String() string {
	switch c {
	case ClassNone:
		return "None"
	case ClassRetryable:
		return "Retryable"
	case ClassInvalid:
		return "Invalid"
	case ClassForbidden:
		return "Forbidden"
	case ClassNotFound:
		return "NotFound"
	case ClassAlreadyExists:
		return "AlreadyExists"
	default:
		return "Unknown"
	}
}

// ErrOperationNotDone — операция kaname ещё идёт.
var ErrOperationNotDone = errors.New("kaname operation is not done yet")

// Classify относит ошибку вызова kaname к классу реакции.
func Classify(err error) Class {
	if err == nil {
		return ClassNone
	}
	var ke *Error
	if errors.As(err, &ke) {
		return classOf(ke.Code)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return ClassRetryable
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return ClassRetryable
	}
	return ClassUnknown
}

// classOf — таблица реакции на код gRPC.
func classOf(c codes.Code) Class {
	switch c {
	case codes.OK:
		return ClassNone
	case codes.Unavailable, codes.DeadlineExceeded, codes.ResourceExhausted, codes.Internal,
		codes.FailedPrecondition, codes.Aborted:
		return ClassRetryable
	case codes.InvalidArgument, codes.OutOfRange:
		return ClassInvalid
	case codes.PermissionDenied, codes.Unauthenticated:
		return ClassForbidden
	case codes.NotFound:
		return ClassNotFound
	case codes.AlreadyExists:
		return ClassAlreadyExists
	default:
		// Canceled, Unknown, Unimplemented, DataLoss и коды вне словаря.
		return ClassUnknown
	}
}

// CodeOf — код gRPC отказа kaname; codes.Unknown, если ошибка не от kaname.
func CodeOf(err error) codes.Code {
	var ke *Error
	if errors.As(err, &ke) {
		return ke.Code
	}
	return codes.Unknown
}
