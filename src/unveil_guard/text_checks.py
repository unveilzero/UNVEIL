"""UNVEIL guard text checks: wording rules for a person's message and for outside content.

``find_rule`` reads one text before a model sees it and returns the first
rule the wording matches, with the wording itself, or ``None``. Outside content is the
result of a tool: a web page, a file, or any other tool output. It is read
with the rules for content. Only a message can cancel the person's own
earlier instructions. The rules are fixed in this file and use no model, so
they run the same with or without one.

Each text is read in two forms. The plain form removes accents, invisible
characters and extra spacing. The folded form also turns look-alike digits,
symbols and letters into the plain letters they stand for.
"""

from __future__ import annotations

import re
import unicodedata
from typing import NamedTuple, Optional

_TARGETS = r"(instructions?|rules|guidelines|prompts?|directives|directions|restrictions|programming|training)"
_ROLE = r"you are|you're|you will be|act as|behave as|pretend to be|pretend you are|role-?play as|respond as|answer as"
_ENCODINGS = r"(base64|rot-?13|hex|binary|morse|cipher)"


def _rules(*rules: tuple[str, str]) -> tuple:
    return tuple((name, re.compile(pattern, re.IGNORECASE)) for name, pattern in rules)


def _instruction_override(own_words: str) -> tuple[str, str]:
    """Wording that tells a model to drop the rules it was given. ``own_words`` is the pattern
    that lets a person cancel their own earlier instructions ("my previous instructions")."""
    return ("instruction_override",
            r"\b(ignore|disregard|forget|override|bypass|discard)\b[^.!?]{0,30}?"
            r"(" + own_words + r"\b(previous|prior|above|earlier|preceding|initial|original)\s+(\w+\s+){0,2}"
            + _TARGETS + r"\b"
            r"|\byour\s+(\w+\s+){0,2}(" + _TARGETS + r"|safeguards|safety|polic(y|ies))\b)"
            r"|\b(ignore|disregard|forget|override|bypass|discard)\s+(all|any|every)\s+(of\s+)?((the|those|these)\s+)?"
            r"(instructions|rules|guidelines|directives)\b")


# The rules that read a person's message and outside content in the same way.
# A gap between the parts of a phrase ends at the end of a sentence, not at a line break.
_SHARED_RULES = _rules(
    # Wording that gives a model a role that has no rules.
    ("unrestricted_persona",
     r"\b(" + _ROLE + r"|from now on)\b[^.!?]{0,80}"
     r"\b(no|without|free of|free from|not bound by|unbound by)\s+((any|all)\s+)?"
     r"(restrictions|rules|limitations|filters|guidelines|ethics|morals|censorship|safeguards)\b"
     r"|\b(" + _ROLE + r"|simulate|stay in)\b[^.!?]{0,60}\b(developer|god|dan|jailbreak|jailbroken)\s+mode\b"
     r"|\b(" + _ROLE + r")\s+(now\s+)?an?\s+(unfiltered|uncensored|unrestricted|amoral|unethical)\b"
     r"|\b(dan|jailbreak|jailbroken)\s+mode\b"
     r"|\bdan\b[\s\S]{0,200}\bdo anything now\b|\bdo anything now\b[\s\S]{0,200}\bdan\b"),
    # Wording that tells a model to switch off its own protections.
    ("safeguard_removal",
     r"\b(disable|turn off|switch off|remove|deactivate|bypass|circumvent|get around|evade)\s+((all|any)\s+)?"
     r"(of\s+)?your\s+(own\s+)?(\w+\s+){0,2}"
     r"(filters?|safeguards?|guardrails?|restrictions|safety|censorship|limitations|moderation|content policy)\b"),
    # Wording that tells a model to follow instructions kept in an encoded form.
    ("encoded_instructions",
     r"\b(decode|decipher|decrypt|translate|unscramble)\b[^.]{0,80}\b" + _ENCODINGS + r"\b[^.]{0,80}"
     r"\b(follow|obey|execute|carry out|comply|do what it says)\b"
     r"|\b(follow|obey|execute|carry out)\b[^.]{0,40}\b" + _ENCODINGS + r"\b[^.]{0,20}"
     r"\b(instructions?|commands?|message|text)\b"),
)

_RULES = _rules(_instruction_override(r"(?<!\bmy\s)")) + _SHARED_RULES

_AI_READER = r"(ai|a\.i\.|llm|(large )?language model|ai assistant|ai agent|chatbot)s?"
# Outside content does not speak for the person, so it gets no pattern for the person's own words.
_CONTENT_RULES = _rules(_instruction_override("")) + _SHARED_RULES + _rules(
    # Wording in content that speaks to the model that reads it.
    ("reader_directive",
     r"\bif you('re| are) an? " + _AI_READER + r"\b"
     r"|\b(instructions?|note|notice|message|attention)\s+(to|for)\s+((the|any|all)\s+)?" + _AI_READER + r"\b"
     r"|\b(do not|don't|never)\s+(tell|inform|notify|alert)\s+the\s+(user|human|person|operator)"
     r"(\s+(about|of|that you|this|anything)\b|\s*([.!\n]|$))"),
)

_SPACING = re.compile(r"[^\S\n]+")
_LOOK_ALIKES = str.maketrans({
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s",
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "і": "i", "у": "y", "х": "x",
})


class Finding(NamedTuple):
    rule: str
    excerpt: str  # the matched wording with a little of the text around it, for the person


def _plain(text: str) -> str:
    kept = (ch for ch in unicodedata.normalize("NFKD", text) if unicodedata.category(ch) not in ("Mn", "Cf"))
    return _SPACING.sub(" ", "".join(kept))


def find_rule(text: str, *, content: bool = False) -> Optional[Finding]:
    """Return the first rule that ``text`` matches, or ``None``."""
    plain = _plain(text)
    for form in (plain, plain.lower().translate(_LOOK_ALIKES)):
        for name, pattern in (_CONTENT_RULES if content else _RULES):
            match = pattern.search(form)
            if match:
                return Finding(name, form[max(0, match.start() - 60):match.end() + 60].strip())
    return None
