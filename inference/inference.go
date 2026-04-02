// SPDX-License-Identifier: MIT

package inference

import (
	"context"

	"github.com/skaphos/wake-core/events"
	"github.com/skaphos/wake-core/report"
)

type Engine interface {
	Synthesize(context.Context, []events.Event) (report.Payload, error)
}
