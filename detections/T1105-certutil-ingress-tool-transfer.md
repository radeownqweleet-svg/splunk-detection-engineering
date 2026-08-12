# Certutil Ingress Tool Transfer (T1105)

| | |
|---|---|
| Tactic | Command and Control (TA0011) |
| Technique | T1105 Ingress Tool Transfer |
| Data source | Sysmon Event ID 1 (Process Create), 3 (Network Connection), 22 (DNS Query) |
| Severity | High |
| Status | tested |

## What it detects

A file downloaded onto an already compromised machine using `certutil.exe`, the built-in
Windows utility for certificates and PKI.

The utility is supposed to reach the internet for certificate revocation lists, so it
ships with an HTTP client and a `-urlcache` switch. An attacker uses that client to
download anything: `certutil -urlcache -split -f <url> <file>`, where `-split` writes the
response body to a file and `-f` forces the operation.

The reasons it gets picked: signed by Microsoft, present on every Windows since XP, often
allowlisted, does not require administrator rights, and its network activity looks like
routine PKI work.

This is not Execution. Certutil downloads the file and stops there; running it is a
separate technique and a separate step. It is also not Delivery in Kill Chain terms.
Delivery is the initial intrusion (phishing, an exploit), while T1105 happens when the
attacker is already inside and is pulling in tooling. The place in the chain looks like
phishing, macro (Execution), macro calls certutil (T1105), payload on disk, payload runs
(Execution), persistence. This rule catches the middle: inside, but not yet established.

Other ways certutil gets abused:

- `-verifyctl -f -split`, the same download through a different switch
- `-decode` and `-encode`, unpacking a payload from base64 (T1140). Malware is carried in
  as text to get past signature scanning and then decoded on the host.
- `-hashfile MD5|SHA1|SHA256`, a hash calculator that saves bringing one along

## Test case

Atomic Red Team T1105, test 7:

```
cmd /c cmd /c certutil -urlcache -split -f https://raw.githubusercontent.com/.../LICENSE.txt Atomic-license.txt
```

## Detection logic

Three event types are correlated by `process_guid`, which is identical across every event
belonging to one process instance and is not reused after a restart.

`OriginalFileName = CertUtil.exe` is used instead of `Image`. The field is read from the
resources compiled into the PE file. Renaming `certutil.exe` to `svc.exe` changes `Image`
but leaves `OriginalFileName` untouched. The only way around it is rebuilding the binary,
which drops the Microsoft signature. `Description` and `Company` behave the same way.

The switches `urlcache` and `split` both have to appear in the command line. Together
they are unambiguous. `-f` is deliberately not required: it adds no confidence, and every
extra condition is another way to miss. Searching for `*-f*` as a substring is useless in
any case, since it matches half of all paths and URLs.

Finally the rule requires Event 1 and either Event 3 or Event 22, so the process did not
merely start but actually reached the network.

That last condition is an OR rather than an AND on purpose. Requiring a DNS query means an
attacker downloading from a raw IP address (`http://185.x.x.x/p.exe`) produces no DNS event
and the rule stays quiet. Every AND narrows the detection and creates a way around it.

## What each event contributes

| EID | Event | Key fields |
|---|---|---|
| 1 | Process Create | `CommandLine`, `OriginalFileName`, `ParentImage`, `Hashes`, `IntegrityLevel`, `CurrentDirectory` |
| 22 | DNS Query | `QueryName`, `QueryResults`, `QueryStatus` |
| 3 | Network Connection | `DestinationIp`, `DestinationPort`, `DestinationHostname` (often empty) |

Events 3 and 22 have no `CommandLine` and no `OriginalFileName`. Event 22 knows the domain
but not the connection, event 3 knows the IP but not the domain. No single event gives the
whole picture, which is the entire point of correlating them.

## SPL

```
index="windows_sysmon"
| stats values(CommandLine) as cl values(EventCode) as ee values(OriginalFileName) as ofn
        min(_time) as FirstTime max(_time) as MaxTime
        values(QueryName) as domain values(DestinationIp) as dst_ip values(DestinationPort) as dst_port
        values(User) as user values(host) as host
        values(ParentImage) as parent values(ParentCommandLine) as parent_cl
        by process_guid
| search ofn="CertUtil.exe" ee=1 (ee=3 OR ee=22) cl="*urlcache*" cl="*split*"
| fieldformat FirstTime=strftime(FirstTime,"%Y-%m-%d %H:%M:%S")
| fieldformat MaxTime=strftime(MaxTime,"%Y-%m-%d %H:%M:%S")
```

## Result

One row, no false positives: the full command line, `ee = 1 22 3`, a 3.4 second activity
window, `dst_port` 80 and 443 (plain HTTP first, then a redirect to HTTPS), four
destination IPs because GitHub sits behind a CDN, and `cmd.exe` as the parent.

Without correlation the same picture would have taken three separate searches.

## Known gaps

- The rule is built on a single test (T1105-7), which is one implementation out of many.
  T1105 also covers `bitsadmin`, `curl`, `Invoke-WebRequest`, `wget` and `scp`. None of
  them are caught here, because the rule is anchored on `ofn="CertUtil.exe"`.
- Even within certutil, `-verifyctl -f -split` downloads a file without `-urlcache`, and
  the rule requires both switches.
- Covering the technique properly is likely several rules, one per family of tools, rather
  than one wide rule.

## Gotchas

- Filtering on `CommandLine` before the first pipe destroys the correlation. A search for
  `CommandLine="*certutil*"` returns Event 1 only, because network and DNS events have no
  such field. `OriginalFileName` behaves the same way. Anything that does not exist on all
  events of the group has to be checked after `stats`, in `search` or `where`.
- `EventCode=1 AND EventCode=22` in the base search is impossible: one event carries one
  EventCode, so the condition is always empty. It only works after grouping.
- `where` does not work with multivalue fields, `search` does. After `stats` the field `ee`
  holds a list; `search ee=22` is true when the list contains that value, `where ee=22` is not.
- `where` is case sensitive, unlike the base search. The log contains `CertUtil.exe` with
  two capitals.
- After `stats` only the collected fields and the grouping field exist. `_time`, `Image`,
  `User` and everything else are gone, and `| table` over them returns nothing.
- `min(_time)` returns epoch. Splunk only renders the real `_time` field nicely.
  `fieldformat` changes the display while keeping the value numeric, so sorting still works.
  `convert ctime()` converts it to a string permanently.
- String markers break first. `certutil -urlcache -split -f ht"t"p://...` runs fine while a
  search for `*http*` walks past it. In cmd the caret (`ht^tp`) and environment variable
  substitution do the same job. That is why the load-bearing signals here are
  `OriginalFileName` and the fact of a network event: a connection cannot be obfuscated,
  it either happened or it did not.
- Windows utilities accept both `-urlcache` and `/urlcache` and ignore case.
- There is no filter before the first pipe, so the rule pulls the entire index into memory
  before grouping. Invisible in a lab, unacceptable in production. The fix is a subsearch
  (collect the interesting `process_guid` values with a narrow search first, then filter the
  main search by that list) or `tstats` over an accelerated data model.
- Parent attribution is misleading. The log shows `powershell -> cmd -> cmd -> certutil`,
  where the doubled `cmd` is an artifact of `Invoke-AtomicTest` and not of the technique.
  A real attack would have one link. The parent is kept out of the detection logic.

## An absent event is not an absent action

Event 11 (FileCreate) never appeared, even though the file really did land on disk.
Event 11 exists in the index, and at the same time it was being written by
`UpdatePlatform.amd64fre.exe` during a Defender update, so the event type works, just not
for this file.

The reason is that common Sysmon configurations (SwiftOnSecurity, Olaf Hartong) filter
FileCreate aggressively down to executables, scripts and shortcuts. Otherwise the volume
would be millions of events per hour. The atomic downloaded a `.txt`, so no file event was
produced.

An event can be missing because of the agent configuration, a filter on the forwarder, or
index settings. An analyst who does not know this closes the case with "the logs are clean".

The consequence for detection: a download rule built only on FileCreate depends on what is
being downloaded. A `payload.exe` would have produced the event.

## Forensics

`-urlcache` leaves traces in `C:\Users\<user>\AppData\LocalLow\Microsoft\CryptnetUrlCache\`.
Even if the downloaded file is deleted, the cache can outlive it, together with the URL it
came from.

## Alert configuration

Scheduled search, time range matched to the cron frequency, triggers on more than 0
results, severity High.

High rather than Medium because the `-urlcache -split` combination plus a confirmed network
connection has almost no legitimate explanation. Severity is set by what the analyst is
required to do, not by how strange the event looks: High means drop everything and
investigate.
