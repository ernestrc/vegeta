package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"

	vegeta "github.com/ernestrc/vegeta/lib"
	"github.com/postmates/go-loadtesting/gnuplot"
)

const usage = `
gnuplot-report [<file>] [options]

Outputs a PNG with the results of a vegeta load test (https://github.com/tsenart/vegeta).

Arguments:
  <file>  A file with vegeta attack results encoded with one of
          the supported encodings (gob | json | csv) [default: stdin]

Options:
  -group  Group results in series with one of the supported aggregations:
          (name | statuscode | failure | nothing) [default: name]

Examples:
  echo "GET http://:80" | vegeta attack -name=50qps -rate=50 -duration=5s > results.50qps.bin
  cat results.50qps.bin | gnuplot-report > plot.50qps.png
  echo "GET http://:80" | vegeta attack -name=100qps -rate=100 -duration=5s > results.100qps.bin
  gnuplot-report results.50qps.bin results.100qps.bin > plot.png
`

var groupBy gnuplot.GroupByMask

func init() {
	groupBy = gnuplot.GroupByName
	flag.Var(&groupByFlag{g: &groupBy}, "group", "")
}

func plotRun(files []string) error {
	dec, mc, err := decoder(files)
	if err != nil {
		return err
	}
	defer mc.Close()

	sigch := make(chan os.Signal, 1)
	signal.Notify(sigch, os.Interrupt)

	p, err := gnuplot.NewGNUPlot(groupBy)
	if err != nil {
		return err
	}
	defer p.Close()

decode:
	for {
		select {
		case <-sigch:
			break decode
		default:
			var r vegeta.Result
			if err = dec.Decode(&r); err != nil {
				if err == io.EOF {
					break decode
				}
				return err
			}

			if err = p.Add(&r); err != nil {
				return err
			}
		}
	}

	_, err = p.WriteTo(os.Stdout)
	return err
}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
		fmt.Fprintf(flag.CommandLine.Output(), usage)
	}
	flag.Parse()
	files := flag.Args()
	if len(files) == 0 {
		files = append(files, "stdin")
	}
	if err := plotRun(files); err != nil {
		fmt.Fprint(os.Stderr, err)
	}
}
