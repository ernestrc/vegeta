package gnuplot

import (
	"io"
	"time"

	vegeta "github.com/ernestrc/vegeta/lib"
)

type testCounts struct {
	failures  float64
	successes float64
}

// outputs a .dat file that GNUPlot is able to understand
type failuresEncoder struct {
	data   map[string]map[time.Time]testCounts
	output io.Writer
}

// NewFailuresEncoder returns a vegeta.Encoder which encodes failures data
// in a format that GNU plot is able to understand
func NewFailuresEncoder(w io.Writer) *failuresEncoder {
	data := make(map[string]map[time.Time]testCounts)
	return &failuresEncoder{data, w}
}

func (e *failuresEncoder) Encode(r *vegeta.Result) error {
	if _, ok := e.data[r.Attack]; !ok {
		e.data[r.Attack] = make(map[time.Time]testCounts)
	}
	second := r.Timestamp.Truncate(time.Second)

	tc := e.data[r.Attack][second]
	if r.Error != "" || (r.Code < 200 && r.Code > 299 && r.Code != 404) {
		tc.failures++
	} else {
		tc.successes++
	}
	e.data[r.Attack][second] = tc
	return nil
}

func collect(i map[time.Time]testCounts) (o map[time.Time]float64) {
	o = make(map[time.Time]float64)

	for k, v := range i {
		t := v.failures + v.successes
		if t == 0 {
			continue
		}
		o[k] = float64(v.failures) / float64(t) * 100.0
	}

	return
}

func (e *failuresEncoder) Flush() (err error) {
	for name, series := range e.data {
		dps := sorted(collect(series))
		if err = writeSeries(e.output, name, dps); err != nil {
			return
		}
	}
	return nil
}
