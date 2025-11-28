package grant

type options struct {
	skipNotification     bool
	skipRevokeInProvider bool
	dryRun               bool
}

type Option func(*options)

func SkipNotifications() Option {
	return func(opts *options) {
		opts.skipNotification = true
	}
}

func SkipRevokeAccessInProvider() Option {
	return func(opts *options) {
		opts.skipRevokeInProvider = true
	}
}

func DryRun() Option {
	return func(opts *options) {
		opts.dryRun = true
	}
}

func (s *Service) getOptions(opts ...Option) options {
	var o options
	for _, fn := range opts {
		fn(&o)
	}
	return o
}
