# Home SOC Lab — Detection Engineering

Hands-on Security Operations Center lab for practicing detection engineering. Rules are written in SPL and mapped to the MITRE ATT&CK matrix.

Built on 2 machines: an Ubuntu machine hosting Splunk and a Windows machine with Atomic Red Team for testing.

## Lab Setup

Ubuntu VM: Splunk Enterprise with 2 indexes: windows_sysmon (Sysmon telemetry, sourcetype XmlWinEventLog) and windows_basic_logs (native Windows logs: Application, Security, System).

Windows VM: the monitored endpoint. Sysmon writes its events to the Microsoft-Windows-Sysmon/Operational channel. A Splunk Universal Forwarder reads the channels listed in inputs.conf and ships them to the indexer. Attack techniques are executed on this machine with Atomic Red Team.

## Methodology

Each rule goes through the same steps.

1. Pick a technique from the ATT&CK matrix and read what the atomic tests actually do
   (`Invoke-AtomicTest <ID> -ShowDetailsBrief`).
2. Execute the test on the Windows endpoint.
3. Collect the telemetry it produced and work out which Event IDs and which fields carry
   the technique. Different tests for the same technique often produce different events.
4. Write the rule in SPL, choosing signals that are hard for an attacker to change.
5. Confirm it fires on the attack and stays quiet on normal activity.
6. Document the logic, the false positives and the boundaries of the rule.
7. Run `-Cleanup` so the next test starts from a clean state.


## Detections

| Technique | Detection | Sysmon Events | Severity |
|---|---|---|---|
| T1059.001 | [PowerShell Download Cradle](detections/T1059.001-powershell-download-cradle.md) | 1 | High |
| T1059.003 | [Windows Command Shell](detections/T1059.003-windows-command-shell.md) | 1 | Medium |
| T1105 | [Certutil Ingress Tool Transfer](detections/T1105-certutil-ingress-tool-transfer.md) | 1, 3, 22 | High |
| T1547.001 | [Registry Run Key Persistence](detections/T1547.001-registry-run-key-persistence.md) | 1, 13 | Medium |

## Coverage & Limitations

Most of the rules here were written against a single atomic test, so the coverage of each technique
is partial. One test is one implementation, not the technique.

The rules run in a lab with one endpoint. False positive rates in a production environment
would be different, and the tuning in these files does not account for that.

