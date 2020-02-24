package gnuplot

import (
	"fmt"
	"io"
	"time"

	"github.com/bradfitz/slice"
)

const kGNUTimeFormat = "15:04:05.999"

type dataPoint struct {
	y time.Time
	x float64
}

func sorted(i map[time.Time]float64) (o []dataPoint) {
	o = make([]dataPoint, len(i))

	var n int
	for k, v := range i {
		o[n] = dataPoint{k, v}
		n++
	}

	slice.Sort(o[:], func(i, j int) bool {
		return o[i].y.Unix() < o[j].y.Unix()
	})

	return
}

func writeSeries(output io.Writer, name string, dps []dataPoint) (err error) {
	if _, err = output.Write([]byte(fmt.Sprintf("%s\n", name))); err != nil {
		return
	}
	for _, dp := range dps {
		if _, err = output.Write([]byte(fmt.Sprintf("%s %f.1\n", dp.y.Format(kGNUTimeFormat), dp.x))); err != nil {
			return
		}
	}

	if _, err = output.Write([]byte("\n\n")); err != nil {
		return
	}
	return
}
