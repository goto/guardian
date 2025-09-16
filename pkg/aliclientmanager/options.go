package aliclientmanager

type Option[T any] func(*Manager[T])

func WithValidationRegionId[T any](id string) Option[T] {
	return func(m *Manager[T]) {
		m.validationRegionId = id
	}
}
