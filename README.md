# 🛡️ LinuxShield — Linux Security Auditor

**Created by Kakar**

LinuxShield is an open-source, read-only Linux security auditing tool built with Python. It checks selected system security configurations, identifies potential issues, provides remediation suggestions, and generates JSON and HTML reports.

Designed for Linux learners, cybersecurity students, and system administrators, LinuxShield offers a simple terminal interface for performing basic security checks.

> **Disclaimer:** LinuxShield is an educational MVP. Its checks and security score are heuristic and do not replace a professional security audit.

## ✨ Features

- 🔍 **Security Scanning** — Inspect selected Linux security settings.
- 🔐 **SSH Configuration Review** — Check common SSH root-login and password-authentication settings.
- 🧱 **Firewall Checks** — Detect UFW or firewalld when available.
- 📁 **File Permission Checks** — Review permissions on `/etc/shadow` and `/etc/sudoers`.
- 📊 **Heuristic Security Score** — Display a basic score based on implemented checks.
- 🎨 **Interactive Terminal UI** — Navigate the tool using a colorful terminal menu.
- 📋 **Scan Findings** — Display findings and remediation recommendations.
- 📄 **HTML Reports** — Generate a readable security audit report.
- 🧾 **JSON Reports** — Export findings in JSON format.
- 💻 **System Information** — Display basic platform and Python information.
- 🛡️ **Read-Only Approach** — No automatic system remediation or intentional network probing.

## 🖥️ Menu Options

When you start LinuxShield, you can choose from the interactive menu:

| Option | Description |
|---|---|
| `1` | Run a new security scan |
| `2` | View the latest saved scan findings |
| `3` | Generate an HTML report |
| `4` | Generate a JSON report |
| `5` | Display system information |
| `0` | Exit LinuxShield |

The latest scan is saved locally so you can review its findings later. Report and history behavior depends on the installed version.

## ⚙️ Requirements

- Python 3.10 or newer
- Linux recommended (Kali Linux, Debian, Ubuntu, and similar distributions)
- Git
- No third-party Python packages required by the current MVP

## 🚀 Installation

### 1. Clone the repository

Replace `YOUR-USERNAME` with your GitHub username.

```bash
git clone https://github.com/YOUR-USERNAME/LinuxShield.git
cd LinuxShield
```

### 2. Create a virtual environment

```bash
python3 -m venv .venv
```

### 3. Activate the environment

```bash
source .venv/bin/activate
```

### 4. Install LinuxShield

```bash
python -m pip install -e .
```

### 5. Start the tool

```bash
linuxshield
```

## 📄 Generate Reports from the Terminal

Generate a JSON report:

```bash
linuxshield --json report.json
```

Generate an HTML report:

```bash
linuxshield --html report.html
```

Generate both reports:

```bash
linuxshield --json report.json --html report.html
```

You can also run LinuxShield without installing it:

```bash
python -m linuxshield.cli
```

## 🧪 Run Tests

From the project root, run:

```bash
python -m unittest discover -s tests -v
```

## 🔒 Safety and Limitations

- Run LinuxShield only on systems you own or are authorized to assess.
- The tool is intended for defensive security auditing and education.
- Root privileges are not normally required.
- Some checks may return limited information when run without elevated privileges.
- The SSH review reads the main `/etc/ssh/sshd_config` file and does not fully resolve included files, `Match` blocks, or effective configuration.
- Detecting a firewall command does not prove that all firewall layers are enabled or correctly configured.
- The security score is a simple heuristic, not a certified security rating.
- LinuxShield does not automatically change system configuration.
- Review findings manually before applying any recommended changes.

## 🗺️ Roadmap

- [ ] Add more distribution-aware security checks
- [ ] Improve SSH effective-configuration analysis
- [ ] Add listening-socket inventory with clear scope and limitations
- [ ] Add historical scan comparison
- [ ] Expand automated tests and continuous integration
- [ ] Improve terminal UI and report formatting
- [ ] Explore an optional web dashboard
- [ ] Add optional AI-powered explanations using a user-provided API key

## 🤝 Contributing

Contributions, bug reports, suggestions, and pull requests are welcome.

When contributing:

1. Describe the issue or proposed improvement.
2. Include tests for new functionality where practical.
3. Keep security checks non-destructive by default.
4. Avoid unauthorized access, destructive actions, or unnecessary network probing.

## 📜 License

LinuxShield is distributed under the **MIT License**. See the [`LICENSE`](LICENSE) file for details.

## 👨‍💻 Author

**Kakar**

Created as an educational cybersecurity project to explore Linux security auditing, Python development, and defensive security practices.

---

⭐ If you find LinuxShield useful, consider starring the repository and contributing to its development.

**LinuxShield — Detect. Analyze. Secure.**
