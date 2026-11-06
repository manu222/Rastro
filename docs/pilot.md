# Running a pilot in a SOC

The test suite proves the tool reads evidence and applies rules the way other
engines do. It cannot prove the report helps an analyst close a ticket in your
environment, with your rules and your collection. A pilot is how you find out,
and it has two halves: closed incidents first, to measure, then open ones, to
use.

## What it needs

- The rules your SOC already runs, as Sigma (`-rules <dir>`). The rules in this
  repository are a test bench, not a recommendation.
- Evidence as it leaves your collection: EVTX files, `audit.log`, Zeek logs, or
  Windows events as a shipper writes them (one JSON object per line). If your
  evidence arrives another way, the report says how many records it could not
  read; that number is the first thing to look at.
- One analyst who knows the incidents, and one hour per incident.

Nothing is installed on the endpoints and nothing leaves the analyst's machine.
The tool is one binary with no external programs on the analysis path.

## Half one: closed incidents

Pick five to ten closed tickets with evidence still available, at least two
that spanned more than one day and one where the conclusion was "benign".

For each, before running anything, the analyst who closed it writes down the
answers: which machines, which accounts, how it got in, what it did, where it
talked, whether it moved, whether it stayed. That sheet is the ground truth.
Writing it after seeing the report would grade the report against itself.

Then:

```
rastro report -rules <your rules> -out INC-1234.html <evidence of INC-1234>
rastro report -rules <your rules> -out INC-1234.json <evidence of INC-1234>
```

Score each question the way `docs/ticket-apt29.md` does:

- **answered**: the report gives the ticket's answer and shows where it came
  from (the record, and the reason when the value is deduced);
- **unanswered**: the report says it does not know;
- **wrong**: the report gives a different answer.

Unanswered is acceptable. Wrong is not, and every wrong answer is a bug report
with the evidence attached, because the design rule is that the tool says "I
don't know" rather than guess.

Also record, per incident: the minutes from evidence to report, the false
positives, and the "What this analysis could not do" section. If that section
says records were unreadable or the capture's completeness is unknown, the
pilot has learned something about your collection, not only about the tool.

## Half two: open incidents

Use it on a live ticket alongside the usual tooling, never instead of it.

Keep each collection in its own folder and link them into one case folder.
After the first run, compare each new run with the previous JSON:

```
rastro report -rules <your rules> -out day1.json case/
rastro report -rules <your rules> -baseline day1.json -out day2.html case/
```

Findings marked new are what the latest collection added. The list of findings
that are no longer produced is not a list of resolved findings: it means the
evidence that produced them is not in this run.

The "What is affected" table has no time window. An account that shows up on a
second machine three days later is the same row, with both machines and the
span listed.

## What decides the pilot

After both halves, three numbers: the share of questions answered, the number
of wrong answers, and the time saved per ticket. The first two come from half
one and are measured; the third comes from half two and is the analysts'
estimate, and should be reported as one.
