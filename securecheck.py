#!/usr/bin/env python3
"""LinuxWays SecureCheck - Security Audit Tool for Arch Linux & Fedora"""
import os, sys, json, subprocess, platform, argparse
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import List, Dict

@dataclass
class Finding:
    category: str
    severity: str
    title: str
    description: str
    recommendation: str
    details: Dict = None
    def to_dict(self):
        return {k: v for k, v in asdict(self).items() if v is not None}

class SystemAuditor:
    def __init__(self):
        self.findings: List[Finding] = []
        self.system_info = {}
        self.distro = self.detect_distro()
        
    def detect_distro(self):
        if os.path.exists("/etc/arch-release"): return "arch"
        elif os.path.exists("/etc/fedora-release"): return "fedora"
        else:
            try:
                with open("/etc/os-release") as f:
                    c = f.read()
                    if "ID=arch" in c or "ID_LIKE=arch" in c: return "arch"
                    elif "ID=fedora" in c: return "fedora"
            except: pass
            return "unknown"
        
    def run_command(self, cmd: str) -> str:
        try:
            result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=10)
            return result.stdout.strip()
        except Exception as e:
            return f"Error: {str(e)}"
    
    def audit_os_info(self):
        self.system_info.update({'os': platform.system(), 'hostname': platform.node(), 'kernel': platform.release(), 'distribution': self.distro, 'timestamp': datetime.now().isoformat()})
        if self.distro == "arch":
            self.system_info['release_info'] = self.run_command("cat /etc/arch-release") or "Arch Linux"
        elif self.distro == "fedora":
            self.system_info['release_info'] = self.run_command("cat /etc/fedora-release") or "Fedora Linux"
        self.findings.append(Finding(category="SYSTEM", severity="INFO", title=f"System Info ({self.distro.upper()})", description=f"Auditing {platform.node()}", recommendation="Review info"))

    def audit_ssh_config(self):
        ssh_configs = ["/etc/ssh/sshd_config"]
        if self.distro == "arch": ssh_configs.append("/etc/ssh/ssh_config")
        for config_file in ssh_configs:
            if not os.path.exists(config_file): continue
            with open(config_file, 'r') as f: content = f.read()
            checks = {'PermitRootLogin': ('no', 'CRITICAL', 'Disable root login'), 'PasswordAuthentication': ('no', 'HIGH', 'Use keys')}
            if self.distro == "fedora": checks['Protocol'] = ('2', 'HIGH', 'Use SSHv2')
            for setting, (expected, severity, rec) in checks.items():
                for line in content.split('\n'):
                    if line.strip().startswith(setting):
                        value = line.split()[-1].strip('"\'')
                        if value.lower() != expected:
                            self.findings.append(Finding(category="SSH", severity=severity, title=f"Insecure SSH: {setting}", description=f"{setting} is {value}", recommendation=rec))

    def audit_firewall(self):
        if self.distro == "fedora":
            status = self.run_command("systemctl is-active firewalld")
            if status == "active": self.findings.append(Finding(category="FIREWALL", severity="INFO", title="Firewalld Active", description="Running", recommendation="Review rules"))
            else: self.findings.append(Finding(category="FIREWALL", severity="HIGH", title="Firewalld Inactive", description="Not running", recommendation="Enable firewalld"))
        elif self.distro == "arch":
            ufw = self.run_command("ufw status 2>/dev/null")
            if "active" in ufw.lower(): self.findings.append(Finding(category="FIREWALL", severity="INFO", title="UFW Active", description="Running", recommendation="Review rules"))
            else: self.findings.append(Finding(category="FIREWALL", severity="CRITICAL", title="No Firewall", description="None detected", recommendation="Install ufw/nftables"))

    def audit_permissions(self):
        paths = [("/etc/shadow", "640"), ("/etc/passwd", "644")]
        if self.distro == "arch": paths.extend([("/etc/pacman.conf", "644")])
        elif self.distro == "fedora": paths.extend([("/etc/selinux/config", "644")])
        for path, exp in paths:
            if os.path.exists(path):
                act = oct(os.stat(path).st_mode)[-3:]
                if act != exp: self.findings.append(Finding(category="PERMISSIONS", severity="HIGH", title=f"Bad Perms: {path}", description=f"Is {act}, should be {exp}", recommendation=f"chmod {exp} {path}"))

    def audit_packages(self):
        if self.distro == "arch":
            ups = self.run_command("pacman -Qu 2>/dev/null | wc -l")
            if ups.isdigit() and int(ups) > 0: self.findings.append(Finding(category="PACKAGES", severity="MEDIUM", title=f"Updates: {ups}", description="Packages outdated", recommendation="sudo pacman -Syu"))
        elif self.distro == "fedora":
            sel = self.run_command("getenforce 2>/dev/null")
            if sel == "Disabled": self.findings.append(Finding(category="SECURITY", severity="HIGH", title="SELinux Disabled", description="No MAC", recommendation="Enable SELinux"))

    def audit_services(self):
        svcs = self.run_command("systemctl list-unit-files --type=service --state=enabled --no-pager 2>/dev/null | grep enabled | wc -l")
        if svcs.isdigit(): self.findings.append(Finding(category="SERVICES", severity="INFO", title=f"Enabled Services: {svcs}", description="Count", recommendation="Review unnecessary services"))

    def generate_report(self, fmt="json"):
        report = {'metadata': {'tool': 'LinuxWays SecureCheck', 'version': '0.1', 'distro': self.distro, 'system': self.system_info}, 'summary': {'total': len(self.findings), 'critical': sum(1 for f in self.findings if f.severity=='CRITICAL'), 'high': sum(1 for f in self.findings if f.severity=='HIGH')}, 'findings': [f.to_dict() for f in self.findings]}
        return json.dumps(report, indent=2) if fmt=="json" else str(report)

    def run_full_audit(self):
        print(f"\nLinuxWays SecureCheck v0.1 - {self.distro.upper()} Audit...\n")
        for name, func in [("OS", self.audit_os_info), ("SSH", self.audit_ssh_config), ("Firewall", self.audit_firewall), ("Perms", self.audit_permissions), ("Packages", self.audit_packages), ("Services", self.audit_services)]:
            print(f"  Auditing {name}..."); func()
        print(f"\nDone! Found {len(self.findings)} issues.\n")



def main():
    parser = argparse.ArgumentParser(
        description='LinuxWays SecureCheck',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('--report', action='store_true', help='Generate JSON report')
    parser.add_argument('--output', type=str, help='Save report to file')
    parser.add_argument('--quick', action='store_true', help='Quick audit')
    parser.add_argument('--category', type=str, 
                       choices=['SSH', 'FIREWALL', 'PERMISSIONS', 'PACKAGES', 'SERVICES'],
                       help='Audit specific category')
    
    args = parser.parse_args()
    auditor = SystemAuditor()
    
    print(f"Detected distribution: {auditor.distro.upper()}")
    
    # Map category names to actual function names
    category_map = {
        'SSH': 'audit_ssh_config',
        'FIREWALL': 'audit_firewall',
        'PERMISSIONS': 'audit_permissions',
        'PACKAGES': 'audit_packages',
        'SERVICES': 'audit_services'
    }

    if args.category:
        func_name = category_map.get(args.category)
        if func_name:
            getattr(auditor, func_name)()
    else:
        if args.quick:
            for func in [auditor.audit_os_info, auditor.audit_ssh_config, auditor.audit_firewall, auditor.audit_permissions, auditor.audit_packages]:
                func()
        else:
            auditor.run_full_audit()
    
    report = auditor.generate_report()
    
    if args.report or args.output:
        if args.output:
            with open(args.output, 'w') as f:
                f.write(report)
            print(f"\nReport saved to: {args.output}")
        else:
            print("\n" + report)
    
    summary = auditor.findings
    if summary:
        print("\nSummary:")
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            count = sum(1 for f in summary if f.severity == severity)
            if count > 0:
                print(f"  {severity}: {count}")

if __name__ == "__main__":
    main()
