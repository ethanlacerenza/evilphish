// This file is adapted from evilginx2 (core/table.go), which itself is a
// modified version of code from the bettercap project
// (https://github.com/bettercap/bettercap) by Simone Margaritelli (@evilsocket).
// Reused here under the GPLv3, consistent with evilphish's own license.
package main

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/fatih/color"
)

var ansiRe = regexp.MustCompile("\033\\[(?:[0-9]{1,3}(?:;[0-9]{1,3})*)?[m|K]")

func viewLen(s string) int {
	for _, m := range ansiRe.FindAllString(s, -1) {
		s = strings.Replace(s, m, "", -1)
	}
	return utf8.RuneCountInString(s)
}

func maxLen(ss []string) int {
	m := 0
	for _, s := range ss {
		if l := viewLen(s); l > m {
			m = l
		}
	}
	return m
}

type alignment int

const (
	alignLeft   = alignment(0)
	alignCenter = alignment(1)
)

func getPads(s string, maxLen int, align alignment) (lPad, rPad int) {
	diff := maxLen - viewLen(s)
	if align == alignCenter {
		lPad = diff / 2
		rPad = diff - lPad + 1
	} else {
		lPad = 0
		rPad = diff - lPad + 1
	}
	return
}

func padded(s string, maxLen int, align alignment) string {
	lPad, rPad := getPads(s, maxLen, align)
	return fmt.Sprintf("%s%s%s", strings.Repeat(" ", lPad), s, strings.Repeat(" ", rPad))
}

// AsRows renders a simple two-column key : value block.
func AsRows(keys []string, vals []string) string {
	clr := color.New(color.FgHiBlack)
	mLen := maxLen(keys)
	var out string
	for i := range keys {
		out += clr.Sprintf(" %s : ", padded(keys[i], mLen, alignLeft)) + fmt.Sprintf("%s\n", vals[i])
	}
	return out
}

// AsTable renders a bordered table with a header row.
func AsTable(columns []string, rows [][]string) string {
	dg := color.New(color.FgHiBlack)
	for i, col := range columns {
		columns[i] = fmt.Sprintf(" %s ", col)
	}
	for i, row := range rows {
		for j, cell := range row {
			rows[i][j] = fmt.Sprintf(" %s ", cell)
		}
	}

	colPaddings := make([]int, 0)
	lineSep := ""
	for colIndex, colHeader := range columns {
		column := []string{colHeader}
		for _, row := range rows {
			column = append(column, row[colIndex])
		}
		mLen := maxLen(column)
		colPaddings = append(colPaddings, mLen)
		lineSep += fmt.Sprintf("+%s", strings.Repeat("-", mLen+1))
	}
	lineSep += "+"

	var table string
	table += dg.Sprintf("%s\n", lineSep)
	for colIndex, colHeader := range columns {
		table += dg.Sprintf("|") + padded(colHeader, colPaddings[colIndex], alignCenter)
	}
	table += dg.Sprintf("|\n")
	table += dg.Sprintf("%s\n", lineSep)
	for _, row := range rows {
		for colIndex, cell := range row {
			table += dg.Sprintf("|") + padded(cell, colPaddings[colIndex], alignLeft)
		}
		table += dg.Sprintf("|\n")
	}
	table += dg.Sprintf("%s", lineSep) + "\n"
	return table
}
