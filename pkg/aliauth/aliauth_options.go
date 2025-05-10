package aliauth

type AliAuthOption interface {
	ApplyTo(c *aliAuth)
}

// ---------------------------------------------------------------------------------------------------------------------
// WithRAMRoleARN
// ---------------------------------------------------------------------------------------------------------------------

// WithRAMRoleARN acs:ram::5123xxx:role/role-name
func WithRAMRoleARN(ramRoleARN string) AliAuthOption {
	return &withRAMRoleARN{ramRoleARN: ramRoleARN}
}

type withRAMRoleARN struct{ ramRoleARN string }

func (w *withRAMRoleARN) ApplyTo(a *aliAuth) { a.ramRoleARN = w.ramRoleARN }
