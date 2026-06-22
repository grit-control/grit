# VHS tape for the GRIT README demo gif.
#
# A terminal gif can't be captured headlessly — this script renders it
# deterministically on your machine.
#
#   1. install VHS:   https://github.com/charmbracelet/vhs   (brew install vhs)
#   2. render:        vhs examples/demo.tape        # writes docs/demo.gif
#   3. embed it: add this line near the top of README.md, under the title:
#                     ![GRIT in action](docs/demo.gif)
#
# Tuning: examples/demo.py prints the whole 10-scene story quickly, so the
# final `Sleep` just holds the last frame. If the gif feels too fast, raise
# the Sleeps; if the file is too big, lower Width/Height or FontSize.

Output docs/demo.gif

Set Shell bash
Set FontSize 15
Set Width 1280
Set Height 800
Set Padding 20
Set Theme "Dracula"

Type "python examples/demo.py"
Sleep 600ms
Enter
Sleep 14s
