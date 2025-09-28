# SIEM-Report-and-Log-analysis-Project  Title: SIEM Security Events Report
 Date Range: 2025-02-04T21:34:36 to 2025-02-05T21:34:36
 Agent ID: 001
 Agent Name: windows
 IP Address: 192.168.14.130
 Operating System: Microsoft Windows 10 Home (10.0.19045.3803)
 Wazuh Version: v4.5.4
 Manager: wazuh-server
1. Executive Summary
 This report provides an analysis of security events detected by the Wazuh SIEM system for 
the agent windows (ID: 001). The report covers the time period from 2025-02-04T21:34:36 to 
2025-02-05T21:34:36. The analysis focuses on the top alerts, rule groups, and security incidents
 detected during this period.
 2. Top Alerts
 The following are the top 5 alerts detected during the reporting period:
 Rule ID
 Description
 752
 Registry Value Entry Added to the System
 Level
 5
 Count
 192
 750
 Registry Value Integrity Checksum Changed
 5
 37
 594
 Registry Key Integrity Checksum Changed
 5
 33
 60106
 Windows logon success.
 3
 8
 598
 Registry Key Entry Added to the System
 5
 6
 Analysis:
  Registry Changes (Rule IDs 752, 750, 594, 598): These alerts indicate frequent changes to the 
Windows registry, which could be a sign of malicious activity or misconfigurations. Registry 
changes are often used by attackers to maintain persistence or modify system settings.
  Windows Logon Success (Rule ID 60106): This alert indicates successful user logins. While this is 
normal, it should be monitored for unusual login patterns or unauthorized access.
 3. Alert Groups Evolution
 The following alert groups were most active during the reporting period:
 Group
 Count
 ossec
 268
 syscheck
 268
 syscheck registry
 268
 syscheck_entry_added
 198
 syscheck_entry_modified
 70
 windows
 24
Group
 windows_security
 Analysis:
 Count
 14
  Syscheck and Registry Changes: The high number of alerts in the syscheck and syscheck 
registry groups indicates frequent file and registry integrity checks. This is a normal part of 
Wazuh's monitoring, but repeated changes should be investigated for potential tampering.
  Windows Security Events: The windows_security group includes events related to 
authentication and system errors, which should be monitored for signs of unauthorized access 
or system failures.
 4.  Top Rule Groups
 The following rule groups were most active during the reporting period:
 Rule Group
 Count
 ossec
 268
 syscheck
 268
 syscheck registry
 268
 windows
 24
 windows_security
 14
 Analysis:
  Ossec and Syscheck: These rule groups are related to file integrity monitoring and registry 
checks. The high count of alerts in these groups suggests that the system is actively monitoring 
for changes, which is a good security practice.
  Windows and Windows Security: These groups include events related to Windows system and 
security logs. The alerts in these groups should be reviewed for potential security incidents
 5. PCI DSS requirements
 The following PCI DSS requirements were triggered during the reporting period:
Rule 
ID
 19013
 19013
 19013
 19012
 Description
 Level
 Count
 CIS Microsoft Windows 10 Enterprise Benchmark v1.12.0: Ensure 'Enforce password 
history' is set to '24 or more password(s)': Status changed from failed to 'not 
applicable'
 5
 1
 CIS Microsoft Windows 10 Enterprise Benchmark v1.12.0: Ensure 'Minimum 
password age' is set to '1 or more day(s)': Status changed from failed to 'not 
applicable'
 5
 1
 CIS Microsoft Windows 10 Enterprise Benchmark v1.12.0: Ensure 'Minimum 
password length' is set to '14 or more character(s)': Status changed from failed to 
'not applicable'
 5
 1
 CIS Microsoft Windows 10 Enterprise Benchmark v1.12.0: Ensure 'Maximum 
password age' is set to '365 or fewer days, but not 0': Status changed from passed to 
'not applicable'
 5
 1
 Analysis:
  Password Policy Changes: These alerts indicate changes to the password policy settings on the 
Windows system. While some changes are expected, they should be reviewed to ensure 
compliance with organizational security policies.
 6. Recommendations
 Based on the findings, the following recommendations are made to improve the security of the system:
 1. Investigate Registry Changes:
 o Review the frequent registry changes (Rule IDs 752, 750, 594, 598) to determine if they 
are legitimate or indicative of malicious activity.
 o Implement stricter controls on registry modifications to prevent unauthorized changes.
 2. Monitor Logon Events:
 o Regularly monitor successful logon events (Rule ID 60106) for unusual patterns or 
unauthorized access.
 o Enable multi-factor authentication (MFA) to reduce the risk of credential theft.
 3. Review Password Policies:
 o Ensure that password policies comply with organizational and regulatory requirements 
(e.g., PCI DSS).
 o Regularly audit password policy settings to detect unauthorized changes.
4. Enhance File Integrity Monitoring:
 o Continue using Wazuh's syscheck module to monitor file and registry integrity.
 o Investigate any unexpected changes detected by the syscheck module.
 5. Set Up Automated Alerts:
 o Configure automated alerts for critical security events, such as registry changes, failed 
logon attempts, and system errors.
 o Ensure that alerts are sent to the appropriate personnel for timely investigation.
 7. Conclusion
 The Wazuh SIEM system detected several security events during the reporting period, including registry 
changes, logon events, and password policy modifications. While some of these events are normal, 
others may indicate potential security risks. By implementing the recommended controls and 
monitoring practices, the security posture of the system can be significantly improved
