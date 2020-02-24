package gnuplot

import (
	"io"
	"time"

	vegeta "github.com/ernestrc/vegeta/lib"
)

// outputs a .dat file that GNUPlot is able to understand
type rateEncoder struct {
	data   map[string]map[time.Time]float64
	output io.Writer
}

// NewRateEncoder returns a vegeta.Encoder which encodes rate data
// in a format that GNU plot is able to understand
func NewRateEncoder(w io.Writer) *rateEncoder {
	data := make(map[string]map[time.Time]float64)
	return &rateEncoder{data, w}
}

func (e *rateEncoder) Encode(r *vegeta.Result) error {
	if _, ok := e.data[r.Attack]; !ok {
		e.data[r.Attack] = make(map[time.Time]float64)
	}
	second := r.Timestamp.Truncate(time.Second)
	e.data[r.Attack][second]++
	return nil
}

func (e *rateEncoder) Flush() (err error) {
	for name, series := range e.data {
		dps := sorted(series)
		if err = writeSeries(e.output, name, dps); err != nil {
			return
		}
	}
	return nil
}
