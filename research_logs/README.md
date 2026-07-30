# Research Logs

> Chronological record of all research activities, experiments, and decisions.

## Purpose

This directory documents the **research process**, not just the results.
A reviewer or future researcher should be able to understand:
- Why decisions were made
- What was tried and failed
- How the design evolved
- What the weekly rhythm of research looked like

## Structure

```
research_logs/
├── README.md               ← this file
├── experiment_template.md  ← template for new entries
├── week01.md               ← 2026-07-07 → 2026-07-13
├── week02.md               ← 2026-07-14 → 2026-07-20
├── week03.md               ← 2026-07-21 → 2026-07-27
└── week04.md               ← 2026-07-28 → 2026-08-03 (current)
```

## Naming Convention

- Files are named `weekNN.md` where NN is zero-padded (week01, week02, ...)
- The date range in each file header indicates the calendar week

## Writing Good Log Entries

A good research log entry:
1. **States objectives** at the start of the week
2. **Records commands run** (exact commands, not paraphrases)
3. **Records results** (numbers, not vague descriptions)
4. **Documents failures** (what failed, why, what you tried)
5. **Links to ADRs** when a significant decision is made
6. **Sets next week objectives**

> *"The difference between science and hacking is written records."*
