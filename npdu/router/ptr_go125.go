package router

func ptr[T any](value T) *T {
	return &value
}
