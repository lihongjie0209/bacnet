package apdu

import "errors"

func ptr[T any](value T) *T {
	return &value
}

func asType[T error](err error) (T, bool) {
	var target T
	ok := errors.As(err, &target)
	return target, ok
}
