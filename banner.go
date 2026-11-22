// evilphish — bridges evilginx3 captures into gophish
// Copyright (C) 2026  Ethan Lacerenza
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
package main

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
)

// VERSION is the build version. It defaults to the embedded value for local
// builds and is overridden at release time via the linker:
//
//	go build -ldflags "-X main.VERSION=v1.0.1"
//
// It is a var (not a const) precisely so -ldflags -X can set it.
var VERSION = "1.0.0"

// sharkPix is a pixel grid traced from the evilphish logo. It is rendered with
// half-block characters (two pixel rows per text line) for high fidelity, so
// the dorsal fin, pointed snout, red eyes and toothy grin all come through.
//
//	#  = shark body / teeth   (white silhouette)
//	o  = eyes                 (red)
//	_  = background           (blank)
const sharkPix = `
___________________________________##___________________________
__________________________________###___________________________
________________________________#####___________________________
________________________________#####___________________________
_______________________________#####____________________________
______________________________#####_____________________________
____________________________#######_____________________________
___________________________########_____________________________
__________________________#########_____________________________
_________________________##########_____________________________
_________________________#############__________________________
_______________________#################________________________
___________________#########################____________________
_________________############################___________________
________________###############################_________________
_______________##################################_______________
______________#####ooo####################ooo#####______________
_____________#####ooooo##################ooooo#####_____________
____________######ooo___o##############o___ooo######____________
________#__######oooo___ooo##########ooo___oooo######__#________
_______##_#######oooo__Hooo##########oooH__oooo#######_##_______
______###_#######ooooooooo############ooooooooo#######_###______
_____####_########oo_ooooo############ooooo_oo########_####_____
____#####_###__####oooooo##############oooooo####__###_#####____
___######_####____############################____####_######___
__#######_####_____##########################_____####_#######__
#########___###___##________________________##___###___#########
_#########__###___##____#_____####_____#____##___###__#########_
_______####_####_####___##____####____##___####_####_####_______
________###__###_####__###___######___###__####_###__###________
_________###__###_###_#####__######__#####_###_###__###_________
__________##__####__#######_########_#######__####__##__________
___________#___####_____################_____####___#___________
________________####_______##########_______####________________
_________________######__________________######_________________
____________________######____________######____________________
________________________################________________________
________________________________________________________________`

func inkFg(c byte) color.Attribute {
	if c == 'o' {
		return color.FgHiRed
	}
	return color.FgHiWhite
}

func inkBg(c byte) color.Attribute {
	if c == 'o' {
		return color.BgHiRed
	}
	return color.BgHiWhite
}

// printShark renders the grid two rows at a time using the upper/lower
// half-block glyphs, doubling vertical resolution.
func printShark() {
	rows := strings.Split(strings.Trim(sharkPix, "\n"), "\n")
	width := 0
	for _, r := range rows {
		if len(r) > width {
			width = len(r)
		}
	}
	for i, r := range rows {
		if len(r) < width {
			rows[i] = r + strings.Repeat("_", width-len(r))
		}
	}
	if len(rows)%2 == 1 {
		rows = append(rows, strings.Repeat("_", width))
	}
	for r := 0; r < len(rows); r += 2 {
		top, bot := rows[r], rows[r+1]
		var b strings.Builder
		for i := 0; i < width; i++ {
			t, d := top[i], bot[i]
			switch {
			case t == '_' && d == '_':
				b.WriteByte(' ')
			case d == '_':
				b.WriteString(color.New(inkFg(t)).Sprint("▀")) // upper half
			case t == '_':
				b.WriteString(color.New(inkFg(d)).Sprint("▄")) // lower half
			default:
				b.WriteString(color.New(inkFg(t), inkBg(d)).Sprint("▀"))
			}
		}
		fmt.Fprintln(color.Output, b.String())
	}
}

// Banner prints the startup splash: the shark, the wordmark and the version.
func Banner() {
	red := color.New(color.FgHiRed, color.Bold)
	gray := color.New(color.FgHiBlack)
	green := color.New(color.FgGreen)

	fmt.Fprintln(color.Output)
	printShark()
	fmt.Fprintln(color.Output)

	fmt.Fprintf(color.Output, "                 %s%s\n",
		red.Sprint("evilphish"), gray.Sprint("  —  blood in the water"))
	fmt.Fprintf(color.Output, "      %s%s\n\n",
		gray.Sprint("evilginx3 → gophish bridge        version "), green.Sprint(VERSION))
}
