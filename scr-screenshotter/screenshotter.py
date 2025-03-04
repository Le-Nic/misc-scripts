import pyautogui
import time
import os
import pandas as pd

# Load CSV with file names and line numbers
csv_file = "files.csv"
df = pd.read_csv(csv_file)

# Folder to save screenshots
save_dir = "screenshots"
os.makedirs(save_dir, exist_ok=True)

print("Open your VS Code, sleeping for 10 seconds...")
time.sleep(10)  # Give time to focus on VS Code

# Function to take a screenshot of a region (adjust coordinates)
def take_screenshot(file_name, line_number):
    x, y, width, height = 460, 29, 1300, 1100  # Adjust this for your VS Code layout
    screenshot = pyautogui.screenshot(region=(x, y, width, height))
    screenshot.save(os.path.join("screenshots", f"{index+1:03}.png"))

# Iterate through each file and line number in CSV
for index, row in df.iterrows():
    file_name = row["file_name"]
    line_number = row["line_number"]

    print(f"Processing {file_name}, Line {line_number}...")

    # Open file in VS Code (Ctrl+P, type filename, press Enter)
    pyautogui.hotkey("ctrl", "p")
    time.sleep(1)  # Wait for input box to appear
    pyautogui.write(file_name)
    time.sleep(1)
    pyautogui.press("enter")
    time.sleep(1)  # Wait for file to load

    # Jump to the specific line (Ctrl+G, type line number, press Enter)
    pyautogui.hotkey("ctrl", "g")
    time.sleep(1)
    pyautogui.write(str(line_number))
    time.sleep(1)
    pyautogui.press("enter")
    time.sleep(1)  # Wait for VS Code to adjust view

    # Take the screenshot
    take_screenshot(file_name, index)
    pyautogui.hotkey("ctrl", "w")
    time.sleep(1)


print("Screenshots completed!")
