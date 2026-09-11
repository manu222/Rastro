# Rule templates

One skeleton per telemetry source. Each carries the correct `logsource`, the
right event block, and — the part that actually saves time — **the real field
names for that event**, extracted from the samples in `datasets/` rather than
copied from documentation.

## Which one do I need?

Start from the question you are trying to answer, not from the attack.

| The question | Template | Event |
| --- | --- | --- |
| What ran, and what launched it? | `sysmon_01_process_creation.yml` | Sysmon 1 |
| What connected where? | `sysmon_03_network_connection.yml` | Sysmon 3 |
| What DLL got loaded into what? | `sysmon_07_image_load.yml` | Sysmon 7 |
| Who opened a handle to whose memory? | `sysmon_10_process_access.yml` | Sysmon 10 |
| What process wrote which file? | `sysmon_11_file_created.yml` | Sysmon 11 |
| What was written to the registry? | `sysmon_12_13_registry.yml` | Sysmon 12/13/14 |
| What named pipe appeared? | `sysmon_17_18_named_pipe.yml` | Sysmon 17/18 |
| Logons, accounts, groups, directory access | `windows_security_channel.yml` | Security / System |
| What did PowerShell actually execute? | `windows_powershell_scriptblock.yml` | PowerShell 4104 |

If two templates could fit, prefer the Sysmon one: it is richer and quieter than
the equivalent built-in log.

## How to use one

1. Copy it into `rules/windows/` and rename it after the behaviour it detects.
2. Generate an id — `[guid]::NewGuid()` in PowerShell — and never reuse another
   rule's.
3. **Look at a real event before writing anything.** The field list in the
   template tells you what exists; only the sample tells you what the values
   look like:

   ```
   tools\hayabusa\hayabusa-4.0.0-win-x64.exe search -f "<sample>.evtx" -k "<keyword>" -q
   ```

4. Fill in every `FILL`, delete the header block and the field reference.
5. Run the rule, then write its manifest in `tests/`.

## Two rules that apply to all of them

**Detect the behaviour, not the tool.** A rule keyed on a file name stops working
the moment it is renamed — which costs an attacker two seconds. Key on what the
technique cannot avoid doing.

**A rule that finds nothing is indistinguishable from a rule that cannot fire.**
If your manifest says `total: 0`, add a `negative_control` block so the test
proves the selection still matches something once the exclusions are disabled.
