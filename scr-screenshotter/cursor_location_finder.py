from pynput import mouse
import pyautogui

def on_click(x, y, button, pressed):
    if pressed and button == mouse.Button.left:
        print(f"Left Click at: X={x}, Y={y}")

# Start listening for mouse events
with mouse.Listener(on_click=on_click) as listener:
    print("Click anywhere to get the coordinates. Press Ctrl+C to stop.")
    listener.join()
