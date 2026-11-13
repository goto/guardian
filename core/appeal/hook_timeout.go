package appeal

import (
	"errors"
	"time"
)

const DefaultPostHookTimeout = 30 * time.Minute

// Configure during startup. Hooks retain their existing detached execution, with
// a finite lifetime independent of a caller closing its HTTP connection.
func (s *Service) ConfigurePostHookTimeout(seconds int) error {
	if seconds == 0 {
		seconds = int(DefaultPostHookTimeout / time.Second)
	}
	if seconds < 60 || seconds > 24*60*60 {
		return errors.New("post-appeal hook timeout must be between 60 and 86400 seconds")
	}
	s.postHookTimeout = time.Duration(seconds) * time.Second
	return nil
}

func (s *Service) postHookTimeoutDuration() time.Duration {
	if s.postHookTimeout > 0 {
		return s.postHookTimeout
	}
	return DefaultPostHookTimeout
}
