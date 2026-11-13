---
name: playbook-builder
description: Turn a job the user does repeatedly into a saved skill with reusable parts and checks that prove it was done right
version: 1.0.0
category: agent
tags: [playbook, delegation, repeatable, checklist, verification, skills]
status: published
confidence: 1.0
source: builtin
owner: ""
created: "2026-11-13T00:00:00Z"
---

## When to Use

Use when the user describes a job they do again and again and wants it handed over: a weekly report, a recurring email, a data pull, a review routine. Also use when the user corrects a result from an existing playbook, so the correction is kept.

Do not use for a one-off task, or for a job the user cannot yet describe from start to finish.

## Procedure

1. Ask for the job in one sentence. Repeat it back and get a yes before going further.
2. Interview the user, one question at a time, waiting for each answer. Cover every item below, and keep asking until each has a concrete answer:
   - what starts the job and how often it runs
   - each input and exactly where it comes from
   - the steps in the order the user really does them
   - each decision along the way and the rule behind it
   - what the user checks before calling it finished
   - what has gone wrong before
   - the standard or tone the result has to meet
   - what a bad result looks like
3. Mark the approval points. List every step that sends something, publishes, pays, deletes, or changes an account or a setting. Each one becomes a step that stops and asks the user. Never write a playbook that performs these on its own.
4. Draft the playbook in four parts:
   - Procedure: numbered steps in plain words, with each decision written as "if X, then Y".
   - Toolbox: any wording, template, query or checklist the job reuses, written out in full with the user's specifics replaced by [placeholders], followed by one filled-in example.
   - Proof: five to ten checks that decide whether a run is done. Each check must be settled by evidence outside your own judgment: a number traced to its source, a link that loads, a count, a value compared with a reference, a quote matched to a claim. Leave out words like clear, professional or high quality.
   - Approval points: the list from step 3.
5. Show the user the whole draft and ask two questions: what did I get wrong, and what did you forget to tell me. Revise until the user says it is right.
6. Save it with `manage_skills`, action `add`, under a short kebab-case name the user agrees to. Put the procedure in `procedure`, the proof checks in `verification`, and the known failures in `pitfalls`. Place the toolbox and the approval points inside the procedure text. Save it as a draft. The user publishes it; do not publish it for them.
7. When running a saved playbook, finish by running every proof check, fixing what fails, and running them again. Report one line per check with pass or fail and the evidence used. List anything that could not be checked and say why. If more than two checks fail on the first pass, stop and tell the user which step caused it.
8. When the user corrects a result, propose the exact change to the saved playbook and apply it with `manage_skills`, action `patch`, only after the user agrees. A correction that stays in the chat is lost on the next run.

## Pitfalls

- Writing the playbook from the first description. The details that make a job go wrong come out in the interview, usually under "what has gone wrong before".
- Proof checks that restate the goal. "The report is accurate" is not a check. "Every figure matches the source sheet, cell by cell" is.
- Saving passwords, keys or personal data in the toolbox. Use a [placeholder] and name where the user keeps the real value.
- Saving a one-time output as a reusable part. Only keep what the next run will need.
- Treating a saved playbook as permission. It describes how to do the job. Each approval point still needs the user's yes on every run.
- Claiming a step was saved or a file was written when the tool did not confirm it. Say what happened and show the text so the user can keep it.

## Verification

- The saved skill appears in `manage_skills` `list` under the agreed name, as a draft.
- Its verification section holds five to ten checks, and each names the evidence that settles it.
- Every sending, publishing, paying, deleting or account-changing step is listed as an approval point.
- The toolbox contains no real passwords, keys or personal data.
- The user has seen the full text and said it is right.
