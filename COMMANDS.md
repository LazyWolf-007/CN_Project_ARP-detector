# CN ARP Detector — Master Command Sheet

This file records the commands used to work on the project, in the order you will usually need them.

## 0. Current checkpoint

- Project folder: `C:\Users\tejas\CN_Project\arp-detector`
- Environment: Python virtual environment in `.venv`
- Interface shown in the working dashboard: `Intel(R) Wi-Fi 6 AX203`
- Current result: the dashboard starts, captures real ARP packets, displays two hosts, and shows packet logs.
- Still to validate: detection accuracy for conflicting IP-to-MAC mappings and alert behavior.
- Mode: passive observation. This project is not currently demonstrating active blocking.

## 1. Open the project in PowerShell

```powershell
cd C:\Users\tejas\CN_Project\arp-detector
```

Check the current folder and files:

```powershell
Get-Location
Get-ChildItem
```

## 2. Activate the Python virtual environment

```powershell
.\.venv\Scripts\Activate.ps1
```

Your prompt should begin with `(.venv)`.

If PowerShell says the activation script cannot run because script execution is disabled, use this only for the current PowerShell session, then activate again:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

## 3. Check Python and installed packages

```powershell
python --version
python -m pip --version
python -m pip list
```

Check Scapy and Rich:

```powershell
python -c "import scapy; print('Scapy:', scapy.__version__)"
python -c "import rich; print('Rich import OK')"
```

## 4. Check the project files

```powershell
Get-ChildItem
Get-Content .\detector.py -TotalCount 60
Get-Content .\arp_monitor.py -TotalCount 40
Get-Content .\alerts.py -TotalCount 60
```

Check that `ARPMonitor` exists:

```powershell
Select-String -Path .\arp_monitor.py -Pattern "^class ARPMonitor"
python -c "from arp_monitor import ARPMonitor; print('ARPMonitor import OK:', ARPMonitor)"
```

Check Python syntax:

```powershell
python -m py_compile .\detector.py .\arp_monitor.py .\alerts.py
```

## 5. Install dependencies / create a dependency list

If the project has a `requirements.txt`, install from it:

```powershell
python -m pip install -r requirements.txt
```

If it does not have one yet, create it from the active environment after confirming the required packages are installed:

```powershell
python -m pip freeze > requirements.txt
```

Note: `pip freeze` records every package in the active virtual environment. Review `requirements.txt` before committing it.

## 6. Run the working passive dashboard

Open PowerShell **as Administrator** if packet capture permissions require it. Then:

```powershell
cd C:\Users\tejas\CN_Project\arp-detector
.\.venv\Scripts\Activate.ps1
python detector.py --interface "Intel(R) Wi-Fi 6 AX203" --passive --verbose
```

To stop the dashboard safely, press:

```text
Ctrl+C
```

Do not run spoofing tests against your everyday Wi-Fi network. Validate detection later in an isolated lab network you own or are authorized to test.

## 7. Other command-line options

See the CLI help:

```powershell
python detector.py --help
```

The program's known options from the current `detector.py` include:

- `-i` / `--interface`: select the capture interface (required)
- `-l` / `--log`: logging option
- `--passive`: passive monitoring mode
- `--export`: export option
- `--verbose`: verbose output

Check `python detector.py --help` for the exact argument syntax before using optional logging/export flags.

## 8. Git: check whether this folder is already a repository

```powershell
git --version
git status
```

If `git status` says this is not a Git repository, initialize it:

```powershell
git init
git branch -M main
```

## 9. Create a `.gitignore` before adding files

Run this from the project root. It creates/overwrites `.gitignore`, so first inspect any existing file before running it.

```powershell
Get-Content .\.gitignore
```

If there is no existing `.gitignore`, create one:

```powershell
@'
.venv/
venv/
__pycache__/
*.py[cod]
*$py.class
.env
.env.*
!.env.example
*.log
logs/
reports/
exports/
.DS_Store
Thumbs.db
'@ | Set-Content -Encoding utf8 .gitignore
```

Do not commit virtual environments, secrets, personal credentials, or unnecessary capture/log files.

## 10. Review exactly what will go to GitHub

```powershell
git status --short
Get-ChildItem -Force
```

If the repository already has a `.gitignore`, make sure it excludes `.venv/`, logs, exports, and secrets before staging.

Stage the code and documentation:

```powershell
git add .
git status
```

Review the staged changes. If you accidentally staged something sensitive or the `.venv` folder, stop and fix the staging before committing.

## 11. Commit the current checkpoint

```powershell
git commit -m "Checkpoint: working passive ARP monitoring dashboard"
```

If Git asks you to configure your identity, use your own GitHub identity:

```powershell
git config --global user.name "YOUR NAME"
git config --global user.email "YOUR GITHUB EMAIL"
```

Then retry the commit.

## 12. Connect to a GitHub repository and push

First create an **empty repository** on GitHub. Do not add a README or `.gitignore` on GitHub if you have already created them locally.

Replace the URL below with the actual HTTPS URL of your own repository:

```powershell
git remote add origin https://github.com/YOUR-USERNAME/YOUR-REPOSITORY.git
git remote -v
git push -u origin main
```

If `origin` already exists, inspect it instead of adding it again:

```powershell
git remote -v
```

If needed, update it with your real repository URL:

```powershell
git remote set-url origin https://github.com/YOUR-USERNAME/YOUR-REPOSITORY.git
git push -u origin main
```

GitHub may prompt you to authenticate through a browser or credential manager. Never put a password or access token directly in this command sheet.

## 13. Commands for future sessions

Start working:

```powershell
cd C:\Users\tejas\CN_Project\arp-detector
.\.venv\Scripts\Activate.ps1
python detector.py --interface "Intel(R) Wi-Fi 6 AX203" --passive --verbose
```

After stopping the app, see what changed:

```powershell
git status
git diff
```

Save later changes:

```powershell
git add .
git status
git commit -m "Describe the change here"
git push
```

Pull the latest GitHub version before working on another machine:

```powershell
git pull
```

## 14. Useful Git inspection commands

```powershell
git status
git log --oneline --decorate -5
git diff
git diff --staged
git remote -v
```

## 15. Resume checklist

When returning to the project:

1. Open PowerShell in the project folder.
2. Activate `.venv`.
3. Check `git status`.
4. Run the passive dashboard command.
5. Confirm the packet count and packet log update.
6. Continue with controlled validation of the detection/alert logic.

## Important safety and repository notes

- Only capture traffic on networks and interfaces you own or are authorized to monitor.
- Keep this tool in passive mode unless you intentionally implement and validate another mode in an authorized lab.
- Never commit `.venv/`, credentials, access tokens, private keys, `.env` files, or sensitive packet captures.
- The current dashboard working does not, by itself, prove that every spoofing scenario is detected correctly.
