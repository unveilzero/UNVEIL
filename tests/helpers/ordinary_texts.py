"""Ordinary texts on more than one line, for the tests of the UNVEIL text rules.

Each text is the kind of mail, notice or page text that a person gets on a normal day.
"""

ORDINARY_TEXTS = [
    "Hi Dan,\n\nThe build server is down, so we can't do anything now.",
    "Dan Smith\nSales lead\n\nWe can do anything now that the budget is approved",
    "You're on the Pro plan\nUnlimited projects, no limitations",
    "You are subscribed to Weekly Deals\nNo restrictions on how often you use your coupon",
    "act as the team lead this week\nwithout limitations on approvals up to $500",
    "Ignore this email if it was you\nYour safety is important to us",
    "Forget password\nYour privacy policy",
    "Override settings\nYour policy number: 12345",
    "Please disregard\nthe earlier guidelines draft, the new one is attached",
    "To decode the hex values\nsee the table below\nthen execute step 3",
    "Translate the binary log\nrun the parser\nfollow the steps in the runbook",
    "From now on\nThe office opens at 9\nNo filters are needed for the coffee machine",
    "Override\nYour policy number is 12345",
    "Coverage override\nYour policy number is 12345",
    "Settings\nForget\nYour previous rules for this device",
    "Please bypass\nyour usual policy approval for this one-time refund",
    "Mark as read\nIgnore\nAll rules in this folder are paused",
    "Discard\nAll guidelines below are drafts",
    "From now on you can order online, with no\nrestrictions on delivery times",
    "The intern will act as a buyer without any\nrestrictions on budget this week",
]

# Ordinary texts in which one line by itself has the wording of a rule. The line break has no part in the match.
ORDINARY_TEXTS_WITH_RULE_WORDING_ON_ONE_LINE = [
    "Translate the hex dump and follow\nthe runbook",
    "Hi Dan, you are free to do anything now that the review is done",
]
