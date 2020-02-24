package gnuplot

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"strconv"
	"strings"

	vegeta "github.com/ernestrc/vegeta/lib"
)

const cmd = `
set terminal pngcairo enhanced font "arial,12" fontscale 1.0 size 1680, 1050

set multiplot layout 3,1 rowsfirst

unset key

set xdata time
set timefmt "%%H:%%M:%%S"

set key autotitle columnhead
set format y '%%.1f'

set ylabel "Latency (ms)"
plot for [IDX=0:%d] '%s' i IDX u 1:2 w points

set ylabel "Failure Rate (perc)"
plot for [IDX=0:%d] '%s' i IDX u 1:2 w line

set ylabel "Rate (req/s)"
set xlabel "Time"
plot for [IDX=0:%d] '%s' i IDX u 1:2 w line

unset multiplot
`

// GNUPlot represents a structure that is able to process vegeta.Results
// and render a PNG report with latency, failure rates and throughput
type GNUPlot struct {
	seen            map[string]struct{}
	groupBy         GroupByMask
	latency         *latencyEncoder
	tmpLatencyData  *os.File
	rate            *rateEncoder
	tmpRateData     *os.File
	failures        *failuresEncoder
	tmpFailuresData *os.File
}

// GroupBy encodes a type of aggregation to be used by GNUPlot
type GroupByMask uint16

const (
	// GroupByNothing signals GNUPlit to not group series by anything.
	GroupByNothing GroupByMask = 0
	// GroupByName signals GNUPlot to group series by the result "Attack" name. This can be
	// defined by the attack name if using the Vegeta CLI, or programatically with the Targeter.
	GroupByName GroupByMask = 1 << iota
	// GroupByStatusCode signals GNUPlot to group series by HTTP response status code.
	// If HTTP Request couldn't be submitted, the status code used will be 0.
	GroupByStatusCode
	// GroupByFailure is an extension to GroupByName which additionally signals GNUPlot to
	// further separate series by whether request/response succeeded or not:
	// according to the following rules:
	//	- If request was not succesfully submitted or there was a response timeout, that's a FAILURE.
	//	- If request status code of the response is smaller than 200 or greater than 299, that's a FAILURE.
	//	- The rest are considered a SUCCESS.
	GroupByFailure
)

const (
	groupByNameStr    = "name"
	groupByCodeStr    = "statuscode"
	groupByFailureStr = "failure"
	groupByNothingStr = ""
)

func groupByFromString(v string) (g GroupByMask, err error) {
	switch v {
	case groupByNameStr:
		g = GroupByName
	case groupByCodeStr:
		g = GroupByStatusCode
	case groupByFailureStr:
		g = GroupByFailure
	case groupByNothingStr:
		g = GroupByNothing
	default:
		err = fmt.Errorf("unkown GroupByMask string value: %s", v)
	}
	return
}

// GroupByMaskFromString parses string to build a GroupBy value.
func GroupByMaskFromString(v string) (g GroupByMask, err error) {
	chunks := strings.Split(v, "|")
	if len(chunks) == 0 {
		return groupByFromString(v)
	}
	for _, flag := range chunks {
		var iFlag GroupByMask
		if iFlag, err = groupByFromString(flag); err != nil {
			err = fmt.Errorf("could not parse GroupByMask: %s: %s", v, err)
		}
		if iFlag != GroupByNothing {
			g = g | iFlag
		}
	}

	// sanity check
	if g&GroupByStatusCode != 0 && g&GroupByFailure != 0 {
		err = fmt.Errorf("it's redundant to group by failure and status code: %s", v)
	}
	return
}

func (g GroupByMask) String() string {
	str := strings.Builder{}
	if g&GroupByName != 0 {
		str.Write([]byte(groupByNameStr))
	}

	if g&GroupByFailure != 0 {
		if str.Len() != 0 {
			str.WriteRune('|')
		}
		str.Write([]byte(groupByFailureStr))
	}

	if g&GroupByStatusCode != 0 {
		if str.Len() != 0 {
			str.WriteRune('|')
		}
		str.Write([]byte(groupByCodeStr))
	}
	return str.String()
}

// NewGNUPlot will allocate storage for a new GNUPlot structure and initialize it.
// groupBy parameter is a o
func NewGNUPlot(groupBy GroupByMask) (p *GNUPlot, err error) {
	p = new(GNUPlot)
	p.seen = make(map[string]struct{})

	p.tmpLatencyData, err = ioutil.TempFile("", "gnuplot-latency")
	if err != nil {
		return
	}
	p.latency = NewLatencyEncoder(p.tmpLatencyData)

	p.tmpRateData, err = ioutil.TempFile("", "gnuplot-rate")
	if err != nil {
		return
	}
	p.rate = NewRateEncoder(p.tmpRateData)

	p.tmpFailuresData, err = ioutil.TempFile("", "gnuplot-failures")
	if err != nil {
		return
	}
	p.failures = NewFailuresEncoder(p.tmpFailuresData)
	p.groupBy = groupBy

	return
}

// updates the result name so series are grouped-by the sefined groupBy strategy
func (p *GNUPlot) updateResultNameByGroupBy(r *vegeta.Result) {
	if p.groupBy == GroupByNothing {
		r.Attack = "All"
		return
	}

	if p.groupBy&GroupByName == 0 {
		r.Attack = "All"
	}

	if p.groupBy&GroupByStatusCode != 0 {
		if r.Error != "" {
			r.Code = 0 // override
		}
		if r.Attack == "" {
			r.Attack = strconv.FormatInt(int64(r.Code), 10)
		} else {
			r.Attack = fmt.Sprintf("%s:%d", r.Attack, r.Code)
		}
	}

	if p.groupBy&GroupByFailure != 0 {
		if r.Error != "" || (r.Code < 200 && r.Code > 299) {
			if r.Attack == "" {
				r.Attack = "FAILURE"
			} else {
				r.Attack = fmt.Sprintf("%s:FAILURE", r.Attack)
			}
		} else {
			if r.Attack == "" {
				r.Attack = "OK"
			} else {
				r.Attack = fmt.Sprintf("%s:SUCCESS", r.Attack)
			}
		}
	}

	if r.Attack == "" {
		r.Attack = "Series"
	}
	return
}

// Add a vegeta.Result to the total results
func (p *GNUPlot) Add(r *vegeta.Result) (err error) {
	p.updateResultNameByGroupBy(r)

	if _, ok := p.seen[r.Attack]; !ok {
		p.seen[r.Attack] = struct{}{}
	}
	if err = p.latency.Encode(r); err != nil {
		return
	}
	if err = p.rate.Encode(r); err != nil {
		return
	}
	if err = p.failures.Encode(r); err != nil {
		return
	}
	return
}

// WriteTo will write all data into io.Writer in PNG Format
func (p *GNUPlot) WriteTo(w io.Writer) (n int64, err error) {
	p.latency.Flush()
	p.rate.Flush()
	p.failures.Flush()

	attacks := len(p.seen)
	if attacks == 0 {
		err = fmt.Errorf("no results present in data")
		return
	}
	GNUPlotScript := fmt.Sprintf(cmd, attacks, p.tmpLatencyData.Name(),
		attacks, p.tmpFailuresData.Name(), attacks, p.tmpRateData.Name())
	cmd := exec.Command("gnuplot")

	inPipe, err := cmd.StdinPipe()
	if err != nil {
		return
	}
	go func() {
		defer inPipe.Close()
		if _, err = inPipe.Write([]byte(GNUPlotScript)); err != nil {
			return
		}
	}()

	pngBytes := new(bytes.Buffer)
	errBytes := new(bytes.Buffer)
	cmd.Stdout = pngBytes
	cmd.Stderr = errBytes

	if err = cmd.Run(); err != nil {
		err = fmt.Errorf("gnuplot error: %s\n%s", err, string(errBytes.Bytes()))
		return
	}

	var bytesN int
	bytesN, err = w.Write(pngBytes.Bytes())
	n = int64(bytesN)
	return
}

// Close shutdowns all the resources associated with this GNUPlot instance
func (p *GNUPlot) Close() {
	p.tmpLatencyData.Close()
	p.tmpRateData.Close()
	p.tmpFailuresData.Close()
}
