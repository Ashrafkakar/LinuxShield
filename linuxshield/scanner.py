"""Read-only checks for a Linux host. No configuration is changed."""
from __future__ import annotations

import os
import platform
import shutil
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass
class Finding:
    check: str
    severity: str
    title: str
    details: str
    recommendation: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


def _run_readonly(command: list[str], timeout: int = 3) -> tuple[int, str]:
    """Run a known local diagnostic command; never invoke a shell."""
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout, check=False
        )
        return result.returncode, (result.stdout + result.stderr).strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 127, str(exc)


def check_system() -> list[Finding]:
    findings = []
    system = platform.system()
    findings.append(Finding(
        check="system", severity="INFO", title="Operating system detected",
        details=f"{platform.platform()} (kernel: {platform.release()})",
        recommendation="Keep the operating system and supported packages updated."
    ))
    if system != "Linux":
        findings.append(Finding(
            check="system", severity="INFO", title="Non-Linux host",
            details=f"Detected {system}; Linux-specific checks may be unavailable.",
            recommendation="Run LinuxShield on a Linux machine or Linux virtual machine."
        ))
    return findings


def check_ssh() -> list[Finding]:
    """Inspect common sshd config files for a few explicit settings."""
    candidates = [Path("/etc/ssh/sshd_config")]
    config = next((p for p in candidates if p.is_file()), None)
    if config is None:
        return [Finding(
            "ssh", "INFO", "SSH server config not found",
            "Could not read /etc/ssh/sshd_config; the SSH server may not be installed or the path may differ.",
            "If this host runs an SSH server, locate its effective configuration and review it."
        )]

    try:
        lines = config.read_text(errors="replace").splitlines()
    except PermissionError:
        return [Finding(
            "ssh", "INFO", "SSH config permission denied",
            "The current user cannot read the SSH server configuration.",
            "Review the file locally with appropriate privileges; LinuxShield itself does not require root."
        )]

    settings: dict[str, str] = {}
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            settings[parts[0].lower()] = parts[1].strip()

    findings = []
    permit_root = settings.get("permitrootlogin", "unspecified").lower()
    if permit_root in {"yes", "without-password", "prohibit-password"}:
        findings.append(Finding(
            "ssh", "MEDIUM", "Review SSH root-login policy",
            f"PermitRootLogin is set to {permit_root!r} in the main config file.",
            "Prefer PermitRootLogin no when operationally appropriate, and validate the effective sshd configuration before changing anything."
        ))
    else:
        findings.append(Finding(
            "ssh", "INFO", "SSH root-login setting inspected",
            f"PermitRootLogin is {permit_root!r} in the main config file. Included files or Match blocks may change effective behavior.",
            "Use the SSH server's effective-configuration tooling to verify the final setting."
        ))

    password_auth = settings.get("passwordauthentication", "unspecified").lower()
    if password_auth == "yes":
        findings.append(Finding(
            "ssh", "LOW", "SSH password authentication enabled in main config",
            "PasswordAuthentication is set to yes in the main config file.",
            "Consider key-based authentication where suitable; check effective configuration and recovery access before changes."
        ))
    else:
        findings.append(Finding(
            "ssh", "INFO", "SSH password-authentication setting inspected",
            f"PasswordAuthentication is {password_auth!r} in the main config file.",
            "Verify the effective sshd configuration; this basic check does not resolve Include files or Match blocks."
        ))
    return findings


def check_firewall() -> list[Finding]:
    findings = []
    if shutil.which("ufw"):
        code, output = _run_readonly(["ufw", "status"])
        if code == 0 and "Status: active" in output:
            findings.append(Finding("firewall", "INFO", "UFW firewall active", output.splitlines()[0],
                                    "Review firewall rules periodically and allow only required services."))
        elif code == 0 and "Status: inactive" in output:
            findings.append(Finding("firewall", "MEDIUM", "UFW firewall inactive", output.splitlines()[0],
                                    "If this host needs host-based filtering, configure a firewall appropriate to your distribution and environment."))
        else:
            findings.append(Finding("firewall", "INFO", "UFW status could not be confirmed",
                                    output or "No output returned.", "Check firewall status manually; LinuxShield makes no changes."))
        return findings

    if shutil.which("firewall-cmd"):
        code, output = _run_readonly(["firewall-cmd", "--state"])
        if code == 0 and output.strip() == "running":
            findings.append(Finding("firewall", "INFO", "firewalld is running", output,
                                    "Review active zones and rules for least privilege."))
        else:
            findings.append(Finding("firewall", "MEDIUM", "firewalld not confirmed running",
                                    output or "Command did not confirm a running service.",
                                    "Verify which firewall manager your distribution uses before making changes."))
        return findings

    findings.append(Finding(
        "firewall", "INFO", "Supported firewall command not found",
        "Neither ufw nor firewall-cmd was found on PATH; this does not prove that no firewall is active.",
        "Check the firewall tool used by your distribution (for example nftables) and inspect its rules."
    ))
    return findings


def check_sensitive_permissions() -> list[Finding]:
    findings = []
    for path in (Path("/etc/shadow"), Path("/etc/sudoers")):
        try:
            mode = path.stat().st_mode & 0o777
        except FileNotFoundError:
            continue
        except PermissionError:
            findings.append(Finding("permissions", "INFO", f"Could not inspect {path}",
                                    "Permission denied while reading metadata.",
                                    "Review the file permissions locally with an authorized administrator."))
            continue
        # Flag only world-readable sensitive files; avoid asserting all modes are unsafe.
        if mode & 0o004:
            findings.append(Finding(
                "permissions", "HIGH", f"{path} is world-readable",
                f"Detected mode {mode:04o}; the file grants read permission to others.",
                "Investigate immediately and apply distribution-appropriate permissions after confirming service requirements."
            ))
        else:
            findings.append(Finding("permissions", "INFO", f"{path} is not world-readable",
                                    f"Detected mode {mode:04o}.",
                                    "Continue reviewing ownership and permissions against your distribution's defaults."))
    return findings


def run_scan() -> dict[str, Any]:
    findings: list[Finding] = []
    for check in (check_system, check_ssh, check_firewall, check_sensitive_permissions):
        try:
            findings.extend(check())
        except Exception as exc:  # keep a scan useful if one check fails
            findings.append(Finding(
                "internal", "INFO", f"Check {check.__name__} did not complete",
                f"{type(exc).__name__}: {exc}",
                "Review this check's output and rerun in a suitable environment."
            ))

    weights = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1}
    deductions = sum(weights.get(f.severity, 0) for f in findings)
    score = max(0, 100 - min(100, deductions))
    return {
        "tool": "LinuxShield",
        "version": "0.1.0",
        "host": platform.node() or "unknown",
        "platform": platform.platform(),
        "score": score,
        "findings": [f.to_dict() for f in findings],
        "note": "Heuristic starter audit, not a guarantee of security. Some checks inspect only common config paths."
    }
