# main.py
import sys
from gui import AutoYoutubeApp

if __name__ == "__main__":
    try:
        app = AutoYoutubeApp()
        app.mainloop()
    except KeyboardInterrupt:
        print("\nStopped by User.")
        sys.exit(0)