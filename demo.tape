# autopatch demo — autonomous vulnerability discovery & patching
# Usage: vhs demo.tape

Output demo.mp4

Require autopatch

Set Shell "zsh"
Set FontSize 12
Set Width 960
Set Height 500
Set Padding 20
Set Framerate 1
Set Theme "Catppuccin Mocha"
Set TypingSpeed 40ms
Set CursorBlink false

# Title
Type "echo # autopatch — autonomous security patching"
Enter
Sleep 1s

# Show help
Type "autopatch --help"
Enter
Sleep 3s

# Start a run
Type "echo # Point at any repo and let it rip"
Enter
Sleep 500ms

Type "autopatch run ."
Enter
Sleep 20s
Ctrl+C

Type "echo # Inspect the vulnerability queue"
Enter
Sleep 500ms

Type "cat .autopatch/vulnerabilities.jsonl | python -m json.tool"
Enter
Sleep 3s

Sleep 2s
