## What's this?

Simple screenshotter for SCR (99% wouldn't work if its a follow-up though), it simulates clicking and naviating to the file

## How to use?

1. Open vscode with the directory of the source code files
2. Run cursor_location_finder.py
3. Click on the four corners of the vscode where you want the screenshot to be taken
4. Copy the coordinates of the four corners based on the output of cursor_location_finder.py
5. Note the coordinates of the top left corner and calculate the width and height of the screenshot box
6. Insert the values into screenshotter.py
7. Make sure files.csv (which contains the file name and the line number) is present in the same directory 
8. Run screenshotter.py
9. Navigate to vscode and click at any part of vscode so that mouse can focus on that window

## Results?

You should find the screenshots in the same directory specified in screenshotter.py