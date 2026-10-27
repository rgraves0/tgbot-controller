# Telegram Bot Controller & Inspector (tbot_controller.py)

A secure, dual-mode (CLI & Interactive Terminal + Tkinter GUI) Python tool designed for educational purposes, Telegram bot administration, and authorized security testing labs.

## Features

- Dual Interface: Run as an interactive terminal shell, quick CLI one-liners, or a responsive Tkinter GUI.
- Secure Architecture: Built with robust input validation, strict HTTPS webhook verification, and safe file handling (preventing Path Traversal).
- Auto-Chat Harvesting: Automatically captures and caches unique Chat IDs from incoming updates for quick targeting.
- Webhook Management: Inspect, set, or delete webhooks instantly to toggle between webhook mode and long-polling (getUpdates).
- Media Operations: Upload documents/files securely and download files from bots using their file_id.
- Live Message Monitor: Real-time stream monitoring for incoming bot updates.

---

## Prerequisites

- Python 3.8 or higher
- requests library

You can install the required dependency via pip:
pip install requests

---

## Installation Instructions

1. Clone or download the repository to your local machine:
   git clone https://github.com/your-username/telegram-bot-controller.git
   cd telegram-bot-controller

2. Ensure tbot_controller.py is in your working directory.

---

## Usage Instructions

### 1. Interactive Terminal Mode (Recommended)
Launch the interactive menu-driven shell by providing your bot token (or it will prompt you securely):
python tbot_controller.py YOUR_BOT_TOKEN

Or simply run:
python tbot_controller.py

### 2. GUI Mode
Launch the graphical user interface:
python tbot_controller.py YOUR_BOT_TOKEN --gui

### 3. CLI Mode / One-Liners (Automation & Quick Scripting)
- Check Bot Profile & Webhook Status:
  python tbot_controller.py YOUR_BOT_TOKEN --info

- Fetch Update Logs:
  python tbot_controller.py YOUR_BOT_TOKEN --logs

- Delete Webhook (Unlock Polling):
  python tbot_controller.py YOUR_BOT_TOKEN --del-webhook

- Set a New Webhook:
  python tbot_controller.py YOUR_BOT_TOKEN --set-webhook "https://your-domain.com/hook"

- Send a Text Message:
  python tbot_controller.py YOUR_BOT_TOKEN --chat-id "CHAT_ID" --send "Hello from CLI!"

- Upload a Document:
  python tbot_controller.py YOUR_BOT_TOKEN --chat-id "CHAT_ID" --upload "./document.pdf"

- Download a File by file_id:
  python tbot_controller.py YOUR_BOT_TOKEN --download "BQACAgUAAxkBAAI..."

---

## Educational Disclaimer
This tool is created strictly for educational purposes, academic research, and authorized security testing. Do not use this tool against bots or systems without explicit permission from the rightful owners. The author assumes no liability for misuse.

---

## License
This project is open-source under the MIT License.
