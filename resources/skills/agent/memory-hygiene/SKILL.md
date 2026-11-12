---
name: memory-hygiene
description: Decide what to save to memory, save it cleanly, and use saved memory without overtrusting it
version: 1.0.0
category: agent
tags: [memory, context, preferences, recall]
status: published
confidence: 1.0
source: builtin
owner: ""
created: "2026-11-12T00:00:00Z"
---

## When to Use

Use when the user asks you to remember, update, or forget something, when a durable preference or fact comes up that later conversations will need, or when saved memory may bear on the current task.

## Procedure

1. Save only what stays true and stays useful: stated preferences, standing instructions, ongoing projects, and decisions the user made. Skip anything that expires on its own, such as today's errand or a temporary value.
2. Save what the user said, not what you inferred. Record it in their terms and at the level of detail they gave. Keep your own guesses and advice out of memory.
3. Search before adding. If an entry on the same subject exists, update that entry instead of creating a second one.
4. Write each entry as one short, self-contained statement that will make sense with no other context, and include the date when timing matters.
5. Keep secrets out. Never store passwords, keys, tokens, card or account numbers, or identity document numbers, even when asked. Say plainly that you did not save them.
6. When the user asks you to forget something, delete the entry itself and confirm that it is gone. Do not replace it with a note saying it used to be true.
7. Recall with care. Treat a saved entry as a lead that may be out of date. When it matters to the answer, check it against the current conversation or ask.
8. Use memory quietly. Apply a saved preference without announcing that you looked it up, and do not raise saved personal details the user did not bring into this conversation.

## Pitfalls

- Do not store a fact about another person beyond what the user needs you to know to help them.
- Do not let a saved instruction override what the user is asking for now. The current request wins.
- Do not save instructions that would make later answers less honest or less safe, such as "never disagree with me".
- Do not claim something was saved, updated, or deleted unless the memory tool reported success.

## Verification

- Each saved entry is something the user stated, is durable, and contains no secret.
- No two entries describe the same subject.
- A requested deletion was confirmed by the tool's result.
- The reply says what was saved, changed, or declined in one line.
