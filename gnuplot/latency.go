package gnuplot

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"io"
	"strconv"

	vegeta "github.com/ernestrc/vegeta/lib"
)

// outputs a .dat file that GNUPlot is able to understand
type latencyEncoder struct {
	buffers  map[string]*bytes.Buffer
	encoders map[string]*csv.Writer
	output   io.Writer
}

// NewLatencyEncoder returns a vegeta.Encoder which encodes latency data
// in a format that GNU plot is able to understand
func NewLatencyEncoder(w io.Writer) *latencyEncoder {
	buffers := make(map[string]*bytes.Buffer)
	encoders := make(map[string]*csv.Writer)
	return &latencyEncoder{buffers, encoders, w}
}

func (e *latencyEncoder) Encode(r *vegeta.Result) error {
	name := r.Attack
	if _, ok := e.encoders[name]; !ok {
		buf := new(bytes.Buffer)
		e.buffers[name] = buf
		e.encoders[name] = csv.NewWriter(buf)
		e.encoders[name].Comma = ' '
	}

	return e.encoders[name].Write([]string{
		r.Timestamp.Format(kGNUTimeFormat),
		strconv.FormatInt(r.Latency.Nanoseconds()/1000000, 10),
	})
}

func (e *latencyEncoder) Flush() (err error) {
	for series, enc := range e.encoders {
		enc.Flush()
		if err = enc.Error(); err != nil {
			return
		}
		if _, err = e.output.Write([]byte(fmt.Sprintf("%s\n", series))); err != nil {
			return
		}
		if _, err = e.output.Write(e.buffers[series].Bytes()); err != nil {
			return
		}

		if _, err = e.output.Write([]byte("\n\n")); err != nil {
			return
		}
	}
	return nil
}
