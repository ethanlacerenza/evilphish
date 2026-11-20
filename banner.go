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

const VERSION = "2.0.0"

// sharkArt is a pixel grid traced from the evilphish logo (dorsal fin, pointed
// snout, toothy grin):
//
//	#  = shark body / teeth  (rendered as a solid block)
//	o  = eyes                (rendered red)
//	_  = background          (space)
const sharkArt = `
_______________________________##_________________________
_____________________________####_________________________
___________________________#####__________________________
_________________________#######__________________________
_______________________###########________________________
_________________#######################__________________
_______________###########################________________
_____________####ooo__oo#########o__ooo#####______________
_________##_#####oooooooo#######ooooooo######_##__________
______#####_##__###oooo##########oooo####_###_####________
____#######_###___#____#____#____#___#___###__######______
_________###_###_###__##___##___##___###_##_###___________
___________##__###_#_####_####_####_#__###_##_____________
_________________####______________#####__________________
`

func printShark() {
	body := color.New(color.FgHiWhite) // bright silhouette
	eye := color.New(color.FgHiRed)    // glowing red eyes
	const block = "█"

	for _, line := range strings.Split(strings.Trim(sharkArt, "\n"), "\n") {
		var b strings.Builder
		for _, c := range line {
			switch c {
			case '#':
				b.WriteString(body.Sprint(block))
			case 'o':
				b.WriteString(eye.Sprint(block))
			default:
				b.WriteString(" ")
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

	fmt.Fprintf(color.Output, "              %s%s\n",
		red.Sprint("evilphish"), gray.Sprint("  —  how much is the phish?"))

	fmt.Fprintf(color.Output, "   %s%s\n\n",
		gray.Sprint("evilginx3 → gophish bridge        version "), green.Sprint(VERSION))
}
