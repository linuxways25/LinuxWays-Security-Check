from securecheck import SystemAuditor
a = SystemAuditor()
a.audit_os_info()
print(a.generate_report())
