# Record the mcpwn demo as a GIF with charmbracelet/vhs:
#   vhs tools/demo.tape
# Produces assets/demo-recorded.gif from a real terminal run.
# (The committed assets/demo.gif is generated headlessly by tools/gen-gif.mjs,
#  which needs no recorder — use this tape if you prefer a live capture.)

Output assets/demo-recorded.gif

Set FontSize 17
Set Width 900
Set Height 700
Set Padding 20
Set Theme "GitHub Dark"

Type "npm run demo"
Sleep 500ms
Enter
Sleep 6s
