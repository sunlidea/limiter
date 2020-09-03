package limiter_test

import (
	"time"

	"github.com/ulule/limiter/v3"
	"github.com/ulule/limiter/v3/drivers/store/memory"
)

func New() *limiter.Limiter {
	store := memory.NewStore()
	rate := limiter.Rate{
		Period: 1 * time.Second,
		Limit:  int64(10),
	}
	return limiter.New(store, rate)
}
