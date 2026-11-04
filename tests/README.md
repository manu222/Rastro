# Rule tests

Every detection rule in this repository has a test manifest here, named after the
rule file it covers. A manifest states exactly which public attack samples the
rule is expected to match, and how many times.

## Two engines

No single tool reads every kind of evidence, so the suite runs two.

| | Rules | Evidence | Engine |
|---|---|---|---|
| Windows | `rules/windows/` | `datasets/` — EVTX | Hayabusa |
| Linux | `rules/linux/` | `datasets-linux/` — auditd text | Zircolite |

A manifest names the engine it needs in its `engine` field. The field may be
omitted, in which case it means Hayabusa, which is why the Windows manifests
never had to change when the second engine arrived.

A rule left directly in `rules/`, in neither subdirectory, is a hard failure:
nothing would ever execute it, and its manifest would report zero without
explaining why.

## Why manifests instead of committed log files

Neither corpus is copied into this repository.

The Windows samples come from
[EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES), which
is GPL-3.0 licensed. Each manifest pins the dataset commit and references samples
by path, and CI clones the dataset at that commit before running the rules.

The Linux samples come from [attack_data](https://github.com/splunk/attack_data)
(Apache-2.0) and are handled differently, because that repository stores its logs
in Git LFS: a plain clone brings down pointer files rather than data. Instead of
pulling them through the LFS client — which needs the client installed and spends
the upstream project's bandwidth — the files listed in `linux-samples.txt` are
fetched individually over plain HTTPS at a pinned commit. The list doubles as the
declaration of exactly which evidence the Linux rules are tested against.

## What a manifest asserts

Two things, and the second one matters as much as the first:

- **Every listed sample produces the stated number of hits.** A rule that stops
  firing is a regression.
- **The repository-wide total matches.** A rule that starts firing on something
  new is *also* a regression — usually a broken exclusion filter. Checking only
  the positive cases would miss it.

A manifest may also declare a **negative control**, which re-runs the rule with
every exclusion filter neutralised and requires it to match at least a given
number of events. Without it, a rule that can never fire is indistinguishable
from a rule that correctly finds nothing.

## Setting up locally

The Windows side needs the EVTX dataset in `datasets/` and the Hayabusa binary
under `tools/hayabusa/`, both pinned to the versions the CI workflow uses.

The Linux side needs two things:

```
# the evidence
scripts/fetch-linux-samples.sh          # or .ps1 on Windows

# the engine, pinned, with its config directory
git clone --depth 1 --branch v4.7.1 https://github.com/wagga40/Zircolite.git tools/zircolite
pip install ./tools/zircolite
```

Zircolite is cloned rather than installed on its own because it reads its field
mapping from the `config/` directory that ships with the repository; installing
the package alone leaves the mapping behind. The suite runs
`tools/zircolite/zircolite.py`, and `ZIRCOLITE` overrides that path.

Without the tools the suite skips rather than fails, so that a contributor
working on one platform is not blocked by the other. CI sets
`RASTRO_REQUIRE_TOOLS=1`, which turns every skip into a failure — otherwise a
broken setup would report success by quietly running nothing at all.

## Adding a test

1. Run the rule against its dataset and record which files match:

   ```
   # Windows
   hayabusa dfir-timeline -d datasets -r rules/windows -p verbose -o out.csv -a -w -s -q -C -K

   # Linux
   python tools/zircolite/zircolite.py -e datasets-linux -AU -r rules/linux -o out.json
   ```

2. Write a manifest named after the rule, listing each matching sample with its
   hit count and a note explaining what the sample actually contains.
3. Record the total, and the engine if it is not Hayabusa.
4. If the rule has exclusion filters, add a negative control.
