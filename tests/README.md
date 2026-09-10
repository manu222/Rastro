# Rule tests

Every detection rule in this repository has a test manifest here, named after the
rule file it covers. A manifest states exactly which public attack samples the
rule is expected to match, and how many times.

## Why manifests instead of committed log files

The samples come from
[EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES), which
is GPL-3.0 licensed. Rather than redistributing those files, each manifest pins
the dataset commit and references samples by path. CI clones the dataset at that
commit before running the rules, so results are reproducible without copying
anyone else's work into this repository.

## What a manifest asserts

Two things, and the second one matters as much as the first:

- **Every listed sample produces the stated number of hits.** A rule that stops
  firing is a regression.
- **The repository-wide total matches.** A rule that starts firing on something
  new is *also* a regression — usually a broken exclusion filter. Checking only
  the positive cases would miss it.

## Adding a test

1. Run the rule against the dataset and record which files match:

   ```
   hayabusa dfir-timeline -d datasets -r rules/<path-to-rule>.yml -o out.csv -w -s -q -C
   ```

2. Write a manifest named after the rule, listing each matching sample with its
   hit count and a note explaining what the sample actually contains.
3. Record the total.
