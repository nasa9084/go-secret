package secret

import (
	"io"
	"time"
)

// export for testing
func SetRand(r io.Reader) {
	rand = r
}

func SetTimeFunc(t func() time.Time) {
	timeFunc = t
}
