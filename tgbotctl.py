#!/usr/bin/env python3
"""
tbot_controller.py - Telegram Bot Controller & Inspector (CLI + Interactive Shell + GUI)
For Educational & Authorized Security Testing Labs.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

import requests

# ─── CONFIGURATION & CONSTANTS ───────────────────────────────────────────────

API_BASE_URL = "https://api.telegram.org"
DEFAULT_TIMEOUT = (5.0, 30.0)
DOWNLOAD_DIR = Path("./bot_downloads")

TOKEN_PATTERN = re.compile(r"^\d{5,16}:[A-Za-z0-9_-]{30,70}$")


# ─── EXCEPTIONS & VALIDATION ─────────────────────────────────────────────────

class ControllerError(Exception):
    """Base exception for controller validation or API errors."""


def clean_token(raw_token: str) -> str:
    """Clean and validate Telegram Bot Token string."""
    token = raw_token.strip().strip("\"'")
    if token.lower().startswith("bot"):
        token = token[3:]
    if not TOKEN_PATTERN.match(token):
        raise ControllerError(
            "Invalid Bot Token format. (Expected format: 123456789:ABCdefGHIjklMNOpqrSTUvwxYZ)"
        )
    return token


def sanitize_filename(filename: str) -> str:
    """
    Prevent Path Traversal attacks when downloading files from an untrusted bot.
    Strips directory components and dangerous characters.
    """
    base_name = Path(filename).name
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", base_name)
    return cleaned or "downloaded_file.bin"


def validate_webhook_url(url: str) -> str:
    """Ensure webhook URL is valid HTTPS."""
    cleaned = url.strip()
    parsed = urlparse(cleaned)
    if parsed.scheme != "https" or not parsed.netloc:
        raise ControllerError("Webhook URL must be a valid 'https://' URL.")
    return cleaned


# ─── CORE BOT CONTROLLER ENGINE ──────────────────────────────────────────────

class TelegramBotController:
    """Full-featured controller for inspecting and operating a Telegram Bot Token."""

    def __init__(self, token: str, timeout: tuple[float, float] = DEFAULT_TIMEOUT) -> None:
        self.token = clean_token(token)
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "TBotController/3.1"})
        # Automatically stores discovered chats: {chat_id: {"title": ..., "type": ..., "username": ...}}
        self.discovered_chats: dict[str, dict[str, str]] = {}
        self.bot_info: dict[str, Any] = {}

    def _api_call(
        self,
        method: str,
        http_method: str = "GET",
        params: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
        files: dict[str, Any] | None = None,
    ) -> Any:
        url = f"{API_BASE_URL}/bot{self.token}/{method}"
        try:
            resp = self.session.request(
                method=http_method,
                url=url,
                params=params,
                data=data,
                files=files,
                timeout=self.timeout,
            )
            payload = resp.json()
        except requests.exceptions.Timeout as exc:
            raise ControllerError("Request timed out while connecting to Telegram API.") from exc
        except requests.exceptions.RequestException as exc:
            raise ControllerError(f"Network error: {exc}") from exc
        except ValueError as exc:
            raise ControllerError(f"Non-JSON response received from API (HTTP {resp.status_code}).") from exc

        if not isinstance(payload, dict) or not payload.get("ok"):
            err_code = payload.get("error_code", resp.status_code) if isinstance(payload, dict) else resp.status_code
            desc = payload.get("description", "Unknown API Error") if isinstance(payload, dict) else "Invalid Response"
            if err_code == 409:
                raise ControllerError(
                    f"HTTP 409 Conflict: {desc}\n"
                    "[TIP] An active webhook is blocking getUpdates. "
                    "Use Option [4] -> [b] to delete the webhook before fetching logs."
                )
            raise ControllerError(f"API Error [{err_code}]: {desc}")

        return payload.get("result")

    # ── 1. Recon & Status ──

    def get_me(self) -> dict[str, Any]:
        """Fetch bot identity and capabilities."""
        res = self._api_call("getMe")
        self.bot_info = res if isinstance(res, dict) else {}
        return self.bot_info

    def get_webhook_info(self) -> dict[str, Any]:
        """Inspect current webhook configuration (URL, pending updates, errors)."""
        res = self._api_call("getWebhookInfo")
        return res if isinstance(res, dict) else {}

    # ── 2. Webhook Control ──

    def set_webhook(self, url: str, secret_token: str | None = None) -> bool:
        """Redirect/set bot webhook to a target HTTPS server."""
        valid_url = validate_webhook_url(url)
        data: dict[str, Any] = {"url": valid_url}
        if secret_token:
            data["secret_token"] = secret_token.strip()
        return bool(self._api_call("setWebhook", http_method="POST", data=data))

    def delete_webhook(self, drop_pending: bool = False) -> bool:
        """Remove active webhook so getUpdates polling can be used."""
        return bool(
            self._api_call(
                "deleteWebhook",
                http_method="POST",
                data={"drop_pending_updates": drop_pending},
            )
        )

    # ── 3. Updates & Chat Harvesting ──

    def get_updates(self, limit: int = 50, offset: int | None = None) -> list[dict[str, Any]]:
        """Fetch incoming messages/events and auto-harvest Chat IDs."""
        params: dict[str, Any] = {"limit": max(1, min(limit, 100))}
        if offset is not None:
            params["offset"] = offset
        updates = self._api_call("getUpdates", params=params)
        if not isinstance(updates, list):
            return []

        for upd in updates:
            self._harvest_chat_from_update(upd)
        return updates

    def _harvest_chat_from_update(self, update: dict[str, Any]) -> None:
        """Extract chat metadata from any update type and cache it."""
        msg_obj = (
            update.get("message")
            or update.get("edited_message")
            or update.get("channel_post")
            or update.get("my_chat_member")
            or (update.get("callback_query", {}) or {}).get("message")
        )
        if not isinstance(msg_obj, dict):
            return

        chat = msg_obj.get("chat", {})
        if not isinstance(chat, dict) or "id" not in chat:
            return

        cid = str(chat["id"])
        title = chat.get("title") or f"{chat.get('first_name', '')} {chat.get('last_name', '')}".strip()
        self.discovered_chats[cid] = {
            "type": str(chat.get("type", "unknown")),
            "title": title or "Unnamed",
            "username": f"@{chat['username']}" if chat.get("username") else "-",
        }

    # ── 4. Chat Reconnaissance ──

    def get_chat_details(self, chat_id: str) -> dict[str, Any]:
        """Inspect a specific chat/group/channel by ID or @username."""
        info = self._api_call("getChat", params={"chat_id": chat_id.strip()})
        member_count = None
        admins = []
        try:
            member_count = self._api_call("getChatMemberCount", params={"chat_id": chat_id.strip()})
        except ControllerError:
            pass
        try:
            admins = self._api_call("getChatAdministrators", params={"chat_id": chat_id.strip()})
        except ControllerError:
            pass
        return {"info": info, "member_count": member_count, "admins": admins}

    # ── 5. Active Actions (Send / Delete / Upload / Download) ──

    def send_message(self, chat_id: str, text: str) -> dict[str, Any]:
        """Send a text message as the bot."""
        if not chat_id.strip():
            raise ControllerError("Chat ID is required.")
        if not text.strip():
            raise ControllerError("Message text cannot be empty.")
        return self._api_call(
            "sendMessage",
            http_method="POST",
            data={"chat_id": chat_id.strip(), "text": text},
        )

    def delete_message(self, chat_id: str, message_id: int) -> bool:
        """Delete a message in a chat."""
        return bool(
            self._api_call(
                "deleteMessage",
                http_method="POST",
                data={"chat_id": chat_id.strip(), "message_id": int(message_id)},
            )
        )

    def send_document(self, chat_id: str, file_path: str, caption: str | None = None) -> dict[str, Any]:
        """Upload and send a file to a target chat."""
        if not chat_id.strip():
            raise ControllerError("Chat ID is required.")
        path = Path(file_path).expanduser().resolve()
        if not path.is_file():
            raise ControllerError(f"File not found: {path}")

        with path.open("rb") as f:
            return self._api_call(
                "sendDocument",
                http_method="POST",
                data={"chat_id": chat_id.strip(), "caption": caption or path.name},
                files={"document": (path.name, f)},
            )

    def download_file_by_id(self, file_id: str, dest_dir: Path = DOWNLOAD_DIR) -> Path:
        """Download a file from Telegram servers using its file_id safely."""
        file_meta = self._api_call("getFile", params={"file_id": file_id.strip()})
        remote_path = file_meta.get("file_path")
        if not remote_path:
            raise ControllerError("Telegram API did not return a file_path.")

        download_url = f"{API_BASE_URL}/file/bot{self.token}/{remote_path}"
        dest_dir.mkdir(parents=True, exist_ok=True)
        safe_name = sanitize_filename(f"{file_meta.get('file_unique_id', 'file')}_{Path(remote_path).name}")
        target_path = dest_dir / safe_name

        try:
            with self.session.get(download_url, stream=True, timeout=self.timeout) as r:
                r.raise_for_status()
                with target_path.open("wb") as f:
                    for chunk in r.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
        except requests.exceptions.RequestException as exc:
            raise ControllerError(f"Failed to download file: {exc}") from exc

        return target_path


# ─── OUTPUT FORMATTERS ───────────────────────────────────────────────────────

def format_bot_profile(info: dict[str, Any], wh: dict[str, Any] | None = None) -> str:
    lines = [
        f"| Bot ID                      : {info.get('id')}",
        f"| Is Bot                      : {info.get('is_bot')}",
        f"| Name                        : {info.get('first_name', '')}",
        f"| Username                    : @{info.get('username', '')}",
        f"| Can Join Groups             : {info.get('can_join_groups')}",
        f"| Can Read All Group Messages : {info.get('can_read_all_group_messages')}",
        f"| Supports Inline Queries     : {info.get('supports_inline_queries')}",
        f"| Business Enabled            : {info.get('can_connect_to_business')}",
        f"| Has Main Web App            : {info.get('has_main_web_app')}",
        f"| Topics Enabled              : {info.get('has_topics_enabled')}",
    ]
    if wh is not None:
        wh_url = wh.get("url") or "[None - Polling Available]"
        lines.extend([
            "+----------------------------------------------------------",
            f"| Active Webhook URL          : {wh_url}",
            f"| Pending Updates             : {wh.get('pending_update_count', 0)}",
        ])
        if wh.get("ip_address"):
            lines.append(f"| Webhook IP Address          : {wh.get('ip_address')}")
        if wh.get("last_error_message"):
            lines.append(f"| Webhook Last Error          : {wh.get('last_error_message')}")
    return "\n".join(lines)


def format_updates(updates: list[dict[str, Any]]) -> str:
    if not updates:
        return "No update logs found."

    output: list[str] = []
    for u in updates:
        uid = u.get("update_id")
        msg = u.get("message") or u.get("edited_message") or u.get("channel_post")

        if isinstance(msg, dict):
            mid = msg.get("message_id")
            sender = msg.get("from", {})
            chat = msg.get("chat", {})
            text = msg.get("text") or msg.get("caption") or ""

            media_info = ""
            if "document" in msg:
                doc = msg["document"]
                media_info = f"\n| [Document] Name: {doc.get('file_name')} | file_id: {doc.get('file_id')}"
            elif "photo" in msg and isinstance(msg["photo"], list) and msg["photo"]:
                best_photo = msg["photo"][-1]
                media_info = f"\n| [Photo] file_id: {best_photo.get('file_id')}"
            elif "voice" in msg:
                media_info = f"\n| [Voice] file_id: {msg['voice'].get('file_id')}"

            sender_name = f"{sender.get('first_name', '')} {sender.get('last_name', '')}".strip()
            chat_name = chat.get("title") or f"{chat.get('first_name', '')} {chat.get('last_name', '')}".strip()

            block = (
                f"------------------------------------------------------------\n"
                f"| UpdateId       : {uid}\n"
                f"| MessageId      : {mid}\n"
                f"| SenderId       : {sender.get('id')} (Bot: {sender.get('is_bot')})\n"
                f"| SenderName     : {sender_name} (@{sender.get('username', '')})\n"
                f"| ChatId         : {chat.get('id')} [{chat.get('type')}]\n"
                f"| ChatName       : {chat_name} (@{chat.get('username', '')})\n"
                f"| Message        : {text}{media_info}"
            )
            output.append(block)

        elif "my_chat_member" in u:
            mcm = u["my_chat_member"]
            chat = mcm.get("chat", {})
            new_status = mcm.get("new_chat_member", {}).get("status")
            output.append(
                f"------------------------------------------------------------\n"
                f"| UpdateId       : {uid}\n"
                f"| Status Change  : Chat {chat.get('id')} ({chat.get('title', '')}) -> {new_status}"
            )
        else:
            output.append(
                f"------------------------------------------------------------\n"
                f"| UpdateId: {uid} | Keys: {list(u.keys())}"
            )

    return "\n".join(output)


# ─── INTERACTIVE TERMINAL CONTROLLER ─────────────────────────────────────────

def prompt_chat_id(ctrl: TelegramBotController) -> str:
    """Helper to let the user pick from discovered Chat IDs or type a custom one."""
    if ctrl.discovered_chats:
        print("\n[*] Discovered Chat IDs:")
        chat_list = list(ctrl.discovered_chats.items())
        for idx, (cid, meta) in enumerate(chat_list, start=1):
            print(f"  [{idx}] {cid} | {meta['type']} | {meta['title']} ({meta['username']})")
        choice = input("Enter Chat ID (or select index [1, 2...]): ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(chat_list):
            selected_cid = chat_list[int(choice) - 1][0]
            print(f"-> Selected Chat ID: {selected_cid}")
            return selected_cid
        return choice
    return input("Enter Chat ID (or @username): ").strip()


def run_interactive_shell(initial_token: str | None = None) -> None:
    print("=" * 72)
    print("  TELEGRAM BOT CONTROLLER & TAKEOVER LAB (TERMINAL EDITION)")
    print("=" * 72)

    ctrl: TelegramBotController | None = None

    def load_token_interactive(raw: str | None = None) -> None:
        nonlocal ctrl
        tok = raw or input("\n[?] Enter Telegram Bot Token: ").strip()
        ctrl = TelegramBotController(tok)
        me = ctrl.get_me()
        wh = ctrl.get_webhook_info()
        print("\n[OK] Bot connected successfully!")
        print(format_bot_profile(me, wh))

    while ctrl is None:
        try:
            load_token_interactive(initial_token)
        except ControllerError as exc:
            print(f"[!] {exc}")
            initial_token = None
        except (KeyboardInterrupt, EOFError):
            print("\nExiting.")
            return

    while True:
        bot_tag = f"@{ctrl.bot_info.get('username', 'unknown')} ({ctrl.bot_info.get('id', '?')})"
        chat_count = len(ctrl.discovered_chats)
        header = f" Active Bot: {bot_tag} | Discovered Chats: {chat_count} "
        print(f"\n+{header:-^70}+")
        print("| [1] Check Bot Profile & Webhook Status (getMe + getWebhookInfo)      |")
        print("| [2] Fetch Update Logs & Harvest Chat IDs (getUpdates)                |")
        print("| [3] Live Message Monitor (Real-time incoming update stream)          |")
        print("| [4] Webhook Manager (Set / Redirect / Delete Webhook)                |")
        print("| [5] Send Text Message via Bot (sendMessage)                          |")
        print("| [6] Upload & Send File via Bot (sendDocument)                        |")
        print("| [7] Download File from Bot using file_id (getFile)                   |")
        print("| [8] Inspect Chat / Group Details & Admins (getChat)                  |")
        print("| [9] Delete a Message by ID (deleteMessage)                           |")
        print("| [T] Switch to Another Bot Token                                      |")
        print("| [0] Exit Controller                                                  |")
        print("+" + "-" * 70 + "+")

        try:
            cmd = input("Controller > ").strip().upper()

            if cmd == "0":
                print("Exiting controller.")
                break

            elif cmd == "1":
                me = ctrl.get_me()
                wh = ctrl.get_webhook_info()
                print("\n" + format_bot_profile(me, wh))

            elif cmd == "2":
                updates = ctrl.get_updates(limit=50)
                print("\n" + format_updates(updates))
                if ctrl.discovered_chats:
                    print(f"\n[OK] Cached {len(ctrl.discovered_chats)} unique Chat ID(s) in memory.")

            elif cmd == "3":
                print("\n[*] Starting Live Monitor... (Press Ctrl+C to stop)")
                last_offset: int | None = None
                try:
                    while True:
                        upds = ctrl.get_updates(limit=20, offset=last_offset)
                        for u in upds:
                            last_offset = int(u["update_id"]) + 1
                            print(format_updates([u]))
                        time.sleep(2.0)
                except KeyboardInterrupt:
                    print("\n[*] Live Monitor stopped.")

            elif cmd == "4":
                wh = ctrl.get_webhook_info()
                print(f"\nCurrent Webhook URL: {wh.get('url') or '[None]'}")
                print("  [a] Set / Redirect Webhook to HTTPS URL (setWebhook)")
                print("  [b] Delete Webhook & Unlock Polling (deleteWebhook)")
                sub = input("  Select action (a/b): ").strip().lower()
                if sub == "a":
                    new_url = input("  Target HTTPS Webhook URL: ").strip()
                    secret = input("  Secret Token (Optional, press Enter to skip): ").strip() or None
                    ctrl.set_webhook(new_url, secret_token=secret)
                    print(f"  [OK] Webhook redirected to: {new_url}")
                elif sub == "b":
                    drop = input("  Drop pending updates as well? (y/N): ").strip().lower() == "y"
                    ctrl.delete_webhook(drop_pending=drop)
                    print("  [OK] Webhook deleted. You can now use Option [2] to fetch logs.")

            elif cmd == "5":
                cid = prompt_chat_id(ctrl)
                text = input("Message Text: ")
                res = ctrl.send_message(cid, text)
                print(f"[OK] Message sent successfully (Message ID: {res.get('message_id')})")

            elif cmd == "6":
                cid = prompt_chat_id(ctrl)
                fpath = input("File Path to Upload: ").strip().strip("\"'")
                cap = input("Caption (Optional, press Enter to skip): ").strip() or None
                res = ctrl.send_document(cid, fpath, caption=cap)
                print(f"[OK] File uploaded successfully (Message ID: {res.get('message_id')})")

            elif cmd == "7":
                fid = input("Enter file_id to download: ").strip()
                saved_path = ctrl.download_file_by_id(fid)
                print(f"[OK] File downloaded safely -> {saved_path}")

            elif cmd == "8":
                cid = prompt_chat_id(ctrl)
                details = ctrl.get_chat_details(cid)
                cinfo = details["info"]
                print("\n--- Chat Reconnaissance ---")
                print(f"| Chat ID      : {cinfo.get('id')}")
                print(f"| Type         : {cinfo.get('type')}")
                print(f"| Title / Name : {cinfo.get('title') or cinfo.get('first_name', '')}")
                print(f"| Username     : @{cinfo.get('username', '')}")
                print(f"| Description  : {cinfo.get('description') or cinfo.get('bio') or '-'}")
                print(f"| Invite Link  : {cinfo.get('invite_link') or '-'}")
                if details["member_count"] is not None:
                    print(f"| Member Count : {details['member_count']}")
                if details["admins"]:
                    print("| Administrators:")
                    for adm in details["admins"]:
                        u = adm.get("user", {})
                        print(
                            f"    - {u.get('first_name', '')} (@{u.get('username', '')}) "
                            f"[ID: {u.get('id')}] ({adm.get('status')})"
                        )

            elif cmd == "9":
                cid = prompt_chat_id(ctrl)
                mid_str = input("Message ID to delete: ").strip()
                if not mid_str.isdigit():
                    print("[!] Message ID must be numeric.")
                else:
                    ctrl.delete_message(cid, int(mid_str))
                    print(f"[OK] Message ID {mid_str} deleted.")

            elif cmd == "T":
                load_token_interactive(None)

        except ControllerError as exc:
            print(f"\n[!] FAILED: {exc}")
        except (KeyboardInterrupt, EOFError):
            print("\nExiting controller.")
            break


# ─── TKINTER GUI CONTROLLER MODE ─────────────────────────────────────────────

def run_gui_controller(initial_token: str | None = None) -> None:
    try:
        import tkinter as tk
        from tkinter import filedialog
    except ImportError:
        print("[!] Tkinter is not installed. Please use Terminal Mode.", file=sys.stderr)
        sys.exit(1)

    root = tk.Tk()
    root.title("TBot Controller & Inspector (GUI + Terminal Hybrid)")
    root.configure(bg="black")
    root.geometry("950x700")
    root.grid_rowconfigure(3, weight=1)
    root.grid_columnconfigure(0, weight=1)

    status_frame = tk.Frame(root, bg="black")
    status_frame.grid(row=0, column=0, sticky="ew", pady=5, padx=20)

    tk.Label(status_frame, text="| ", fg="white", bg="black", font=("Consolas", 13, "bold")).pack(side=tk.LEFT)
    status_lbl = tk.Label(status_frame, text="Idle", fg="lime", bg="black", font=("Consolas", 13, "bold"))
    status_lbl.pack(side=tk.LEFT)
    tk.Label(status_frame, text=" |", fg="white", bg="black", font=("Consolas", 13, "bold")).pack(side=tk.LEFT)

    input_frame = tk.Frame(root, bg="black")
    input_frame.grid(row=1, column=0, sticky="ew", padx=20)
    input_frame.grid_columnconfigure(1, weight=1)

    botoken_var = tk.StringVar(root, value=initial_token or "")
    chatid_var = tk.StringVar(root)
    message_var = tk.StringVar(root)
    webhook_var = tk.StringVar(root)

    tk.Label(input_frame, text="Bot Token", fg="white", bg="black").grid(row=0, column=0, sticky="w", padx=(0, 10))
    tk.Entry(input_frame, textvariable=botoken_var, bg="#111", fg="lime", insertbackground="lime").grid(
        row=0, column=1, sticky="ew", pady=4
    )

    tk.Label(input_frame, text="Chat ID", fg="white", bg="black").grid(row=1, column=0, sticky="w", padx=(0, 10))
    tk.Entry(input_frame, textvariable=chatid_var, bg="#111", fg="lime", insertbackground="lime").grid(
        row=1, column=1, sticky="ew", pady=4
    )

    tk.Label(input_frame, text="Message", fg="white", bg="black").grid(row=2, column=0, sticky="w", padx=(0, 10))
    tk.Entry(input_frame, textvariable=message_var, bg="#111", fg="lime", insertbackground="lime").grid(
        row=2, column=1, sticky="ew", pady=4
    )

    tk.Label(input_frame, text="Webhook URL", fg="white", bg="black").grid(row=3, column=0, sticky="w", padx=(0, 10))
    tk.Entry(input_frame, textvariable=webhook_var, bg="#111", fg="cyan", insertbackground="cyan").grid(
        row=3, column=1, sticky="ew", pady=4
    )

    log_frame = tk.Frame(root, bg="black")
    log_frame.grid(row=3, column=0, sticky="nsew", padx=20, pady=10)
    log_frame.grid_rowconfigure(0, weight=1)
    log_frame.grid_columnconfigure(0, weight=1)

    scroll = tk.Scrollbar(log_frame)
    scroll.grid(row=0, column=1, sticky="ns")

    textx = tk.Text(
        log_frame,
        bg="black",
        fg="lime",
        insertbackground="lime",
        yscrollcommand=scroll.set,
        wrap=tk.WORD,
        font=("Consolas", 10),
    )
    textx.grid(row=0, column=0, sticky="nsew")
    scroll.config(command=textx.yview)

    def write_log(msg: str) -> None:
        textx.insert("1.0", f"\n------------------------------------------------------------\n{msg}\n")

    def execute_async(status_text: str, color: str, action: Callable[[TelegramBotController], str]) -> None:
        status_lbl.configure(text=status_text, fg=color)
        raw_tok = botoken_var.get()

        def worker() -> None:
            try:
                ctrl = TelegramBotController(raw_tok)
                output = action(ctrl)
                if not chatid_var.get().strip() and ctrl.discovered_chats:
                    first_cid = next(iter(ctrl.discovered_chats.keys()))
                    root.after(0, lambda: chatid_var.set(first_cid))
                root.after(0, lambda: (write_log(output), status_lbl.configure(text="Idle", fg="lime")))
            except Exception as exc:
                root.after(0, lambda: (write_log(f"FAILED: {exc}"), status_lbl.configure(text="Failed", fg="red")))

        threading.Thread(target=worker, daemon=True).start()

    btn_frame = tk.Frame(root, bg="black")
    btn_frame.grid(row=2, column=0, pady=8)

    tk.Button(
        btn_frame,
        text="Check Bot & Webhook",
        bg="yellow",
        width=18,
        command=lambda: execute_async(
            "checking bot", "yellow", lambda c: format_bot_profile(c.get_me(), c.get_webhook_info())
        ),
    ).grid(row=0, column=0, padx=4)

    tk.Button(
        btn_frame,
        text="Check Logs",
        bg="yellow",
        width=14,
        command=lambda: execute_async("fetching logs", "yellow", lambda c: format_updates(c.get_updates())),
    ).grid(row=0, column=1, padx=4)

    tk.Button(
        btn_frame,
        text="Set Webhook",
        bg="magenta",
        fg="white",
        width=14,
        command=lambda: execute_async(
            "setting webhook",
            "magenta",
            lambda c: (c.set_webhook(webhook_var.get()), f"SUCCESS: Webhook -> {webhook_var.get()}")[1],
        ),
    ).grid(row=0, column=2, padx=4)

    tk.Button(
        btn_frame,
        text="Delete Webhook",
        bg="red",
        fg="white",
        width=14,
        command=lambda: execute_async(
            "deleting webhook",
            "red",
            lambda c: (c.delete_webhook(), "SUCCESS: Webhook deleted (Polling unlocked)")[1],
        ),
    ).grid(row=0, column=3, padx=4)

    tk.Button(
        btn_frame,
        text="Send Message",
        bg="lime",
        width=14,
        command=lambda: execute_async(
            "sending message",
            "lime",
            lambda c: (c.send_message(chatid_var.get(), message_var.get()), "SUCCESS: Message sent")[1],
        ),
    ).grid(row=0, column=4, padx=4)

    def gui_upload() -> None:
        fpath = filedialog.askopenfilename()
        if not fpath:
            write_log("FAILED: No file selected")
            return
        execute_async(
            "uploading file",
            "cyan",
            lambda c: (
                c.send_document(chatid_var.get(), fpath),
                f"SUCCESS: File uploaded -> {os.path.basename(fpath)}",
            )[1],
        )

    tk.Button(btn_frame, text="Upload File", bg="cyan", width=14, command=gui_upload).grid(row=0, column=5, padx=4)

    root.mainloop()


# ─── CLI ENTRY POINT ─────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Telegram Bot Controller & Takeover Testing Tool (Terminal & GUI)"
    )
    parser.add_argument(
        "positional_token",
        nargs="?",
        default=None,
        help="Bot Token (e.g., python tbot_controller.py 123456:ABC-DEF...)",
    )
    parser.add_argument("--token", "-t", default=None, help="Specify Bot Token")
    parser.add_argument("--gui", action="store_true", help="Launch Tkinter GUI Mode")

    # Quick one-liner CLI flags
    parser.add_argument("--info", action="store_true", help="Check Bot profile and Webhook info immediately")
    parser.add_argument("--logs", action="store_true", help="Fetch update logs immediately")
    parser.add_argument("--del-webhook", action="store_true", help="Delete active webhook")
    parser.add_argument("--set-webhook", metavar="URL", help="Set a new HTTPS webhook URL")
    parser.add_argument("--chat-id", help="Target Chat ID for sending messages or files")
    parser.add_argument("--send", metavar="TEXT", help="Send a text message directly")
    parser.add_argument("--upload", metavar="FILE", help="Upload a document directly")
    parser.add_argument("--download", metavar="FILE_ID", help="Download a file by file_id")

    args = parser.parse_args()
    token = args.token or args.positional_token or os.environ.get("TELEGRAM_BOT_TOKEN")

    if args.gui:
        run_gui_controller(token)
        return 0

    has_quick_action = any([
        args.info,
        args.logs,
        args.del_webhook,
        args.set_webhook,
        args.send,
        args.upload,
        args.download,
    ])

    if not has_quick_action:
        run_interactive_shell(token)
        return 0

    if not token:
        print("[!] Bot Token is required for one-liner commands.", file=sys.stderr)
        return 1

    try:
        ctrl = TelegramBotController(token)
        if args.info:
            print(format_bot_profile(ctrl.get_me(), ctrl.get_webhook_info()))
        if args.del_webhook:
            ctrl.delete_webhook()
            print("[OK] Webhook deleted successfully.")
        if args.set_webhook:
            ctrl.set_webhook(args.set_webhook)
            print(f"[OK] Webhook set to: {args.set_webhook}")
        if args.logs:
            print(format_updates(ctrl.get_updates()))
        if args.send:
            if not args.chat_id:
                raise ControllerError("--chat-id is required when using --send.")
            ctrl.send_message(args.chat_id, args.send)
            print("[OK] Message sent successfully.")
        if args.upload:
            if not args.chat_id:
                raise ControllerError("--chat-id is required when using --upload.")
            ctrl.send_document(args.chat_id, args.upload)
            print(f"[OK] File uploaded successfully -> {args.upload}")
        if args.download:
            path = ctrl.download_file_by_id(args.download)
            print(f"[OK] File downloaded successfully -> {path}")
        return 0
    except ControllerError as exc:
        print(f"[!] FAILED: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
