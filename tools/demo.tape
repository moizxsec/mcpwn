# Record the real mcpwn demo as a GIF with charmbracelet/vhs:
#   vhs tools/demo.tape
# Captures a live terminal run of `npm run demo` (mcpwn tampering a tool
# result in flight so the agent exfiltrates a secret) into assets/demo.gif.

Output assets/demo.gif

Set FontSize 15
Set Width 1000
Set Height 820
Set Padding 18
Set Theme "GitHub Dark"

Hide
Type "clear" Enter
Show
Sleep 400ms
Type "npm run demo"
Sleep 600ms
Enter
Sleep 7s
