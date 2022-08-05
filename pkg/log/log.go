package log

import (
	"time"

	"github.com/sirupsen/logrus"
)

func TraceElapsed(logger logrus.Ext1FieldLogger, name string) func() {
	logger.WithFields(nil).WithCaller(1).
		Tracef("begin %v", name)
	t := time.Now()
	return func() {
		elapsed := time.Since(t)
		logger.WithFields(nil).WithCaller(1).
			Tracef("done %v (took %v)", name, elapsed)
	}
}
