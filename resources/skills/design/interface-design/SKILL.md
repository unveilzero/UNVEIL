---
name: interface-design
description: Design or review a screen, page, or component so it is clear, consistent, and usable on a phone
version: 1.0.0
category: design
tags: [design, ui, ux, layout, accessibility, frontend]
status: published
confidence: 1.0
source: builtin
owner: ""
created: "2026-11-12T00:00:00Z"
---

## When to Use

Use when the user asks to design, build, restyle, or review a user interface: a web page, an app screen, a form, a dashboard, or a single component.

## Procedure

1. State the job of the screen in one sentence: who uses it and the one thing they must be able to do. Design for that task first and treat everything else as secondary.
2. Reuse what exists. If the project has colors, fonts, spacing, or components already, use them. Invent a new style only where nothing exists, and say that you did.
3. Set a small system before drawing anything: one accent color, one neutral scale, two typefaces at most, one spacing scale, and one corner radius. Derive every later choice from it.
4. Lay out by importance. The most important content and the main action come first and are the most visible. Group related items, and separate groups with space before reaching for lines and boxes.
5. Make it work at phone width first: one column, touch targets at least 44 pixels, body text at least 16 pixels, and no sideways scrolling.
6. Design every state, not only the filled one: empty, loading, error, success, and disabled. Each state tells the user what happened and what to do next.
7. Write the words as part of the design. Label controls by what they do, in the user's own terms. An error message says what went wrong and how to fix it.
8. Check accessibility: text contrast of at least 4.5 to 1, a visible keyboard focus, a label on every input, and no meaning carried by color alone.
9. Remove one thing. Before finishing, look for a decoration, option, or sentence the screen works without, and take it out.

## Pitfalls

- Do not add a library, font service, or image source the project does not already use without saying so.
- Do not style every block as a card. Borders, fills, and shadows mark separate objects; used everywhere they hide the hierarchy.
- Do not center long text or use more than one accent color to make a page feel designed.
- Do not present a design as tested with users, or as accessible, when it was only reasoned about.

## Verification

- The main task can be completed at 400 pixels wide without horizontal scrolling.
- Empty, loading, and error states exist for each data-driven part.
- Every color, size, and spacing value traces back to the small system from step 3.
- The reply names what was reused, what was newly introduced, and what was not checked.
