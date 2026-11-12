---
name: context-budget
description: Finish a task with fewer tool calls and less text read, without losing accuracy
version: 1.0.0
category: agent
tags: [tokens, cost, efficiency, context, performance]
status: published
confidence: 1.0
source: builtin
owner: ""
created: "2026-11-12T00:00:00Z"
---

## When to Use

Use when a task involves several tool calls, long pages or files, repeated lookups, or when the user asks for a cheaper, faster, or shorter run.

## Procedure

1. Before the first tool call, write down the exact facts or outputs the task needs. Every later call should serve an item on that list.
2. Ask narrowly. When a tool accepts a query, a field list, a line range, or a page range, name what you need instead of fetching everything. Fetch a whole document only when the task needs the whole document.
3. Batch what is independent. If several lookups do not depend on each other, request them together in one step.
4. Read a result once and keep the facts. Note the values you need with their source as you go, so you do not fetch or re-read the same thing later.
5. Stop when the list from step 1 is complete. Do not keep searching to confirm an answer that the source already states plainly.
6. Treat a repeated failure as information. If the same call fails twice, change the request or the source. Do not retry it unchanged a third time.
7. Notice truncation. If a result says it was cut or partial, decide whether the missing part matters, then ask for that part specifically or tell the user what you could not see.
8. Keep the reply proportionate. Report the answer, how it was verified, and what remains uncertain. Leave out the step-by-step history unless the user asks for it.

## Pitfalls

- Do not save effort by guessing a value you could look up with one narrow call. Accuracy comes before thrift.
- Do not present part of a page as the whole page. Say which part you read.
- Do not drop verification of numbers, dates, or names that the user will rely on in order to finish sooner.
- Do not re-send large content back to a tool or to the user when a reference to it is enough.

## Verification

- Each tool call maps to an item the task needed.
- No identical call was made more than twice.
- Figures in the answer come from a result that was actually read, with its source named.
- Anything truncated, skipped, or left unverified is stated in the reply.
