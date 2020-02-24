package main

import (
	"github.com/postmates/go-loadtesting/gnuplot"
)

type groupByFlag struct {
	g *gnuplot.GroupByMask
}

func (f *groupByFlag) Set(v string) error {
	value, err := gnuplot.GroupByMaskFromString(v)
	if err != nil {
		return err
	}
	*f.g = value
	return nil
}

func (f *groupByFlag) String() string {
	return f.g.String()
}
