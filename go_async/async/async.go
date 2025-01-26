package async

import "context"

func DefaultValue[T any]() T {
	var value T
	return value
}

type Future[T any] interface {
	Await(ctx context.Context) (T, error)
}

type future[T any] struct {
	await func(ctx context.Context) (T, error)
}

func (f future[T]) Await(ctx context.Context) (T, error) {
	return f.await(ctx)
}

func Exec[T any](f func() T) Future[T] {
	var result T
	c := make(chan struct{})
	go func() {
		defer close(c)
		result = f()
	}()
	return future[T]{
		await: func(ctx context.Context) (T, error) {
			select {
			case <-ctx.Done():
				return DefaultValue[T](), ctx.Err()
			case <-c:
				return result, nil
			}
		},
	}
}
