"""UNVEIL guard text checks: wording rules for a person's message and for outside content.

``find_rule`` reads one text before a model sees it and returns the first
rule the wording matches, with the wording itself, or ``None``. Outside content is the
result of a tool: a web page, a file, or any other tool output. It is read
with the rules for content. Only a message can cancel the person's own
earlier instructions. The rules are fixed in this file and use no model, so
they run the same with or without one.

Each text is read in several forms. The plain form removes accents, characters
with no shape and extra spacing. The folded form also turns look-alike digits,
symbols and letters into the plain letters they stand for. A text with
character references, with characters with no shape, or with letters written
one at a time is read in one more form for each of them.

Text that the characters of a text carry is read as well: text in tag
characters, in variation selectors and in base64. A person does not see that
text when the content is shown, so it is read with the rules for content.
"""

from __future__ import annotations

import base64
import binascii
import html
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
            r"\b(ignore|disregard|forget|override|bypass|discard)\b[^.!?\n]{0,30}?"
            r"(" + own_words + r"\b(previous|prior|above|earlier|preceding|initial|original)\s+(\w+\s+){0,2}"
            + _TARGETS + r"\b"
            r"|\byour\s+(\w+\s+){0,2}(" + _TARGETS + r"|safeguards|safety|polic(y|ies))\b)"
            r"|\b(ignore|disregard|forget|override|bypass|discard)\s+(all|any|every)\s+(of\s+)?((the|those|these)\s+)?"
            r"(instructions|rules|guidelines|directives)\b"
            # The same wording in Spanish, French, German and Chinese.
            r"|\bignora\s+(todas\s+)?las\s+instrucciones\s+(anteriores|previas)\b"
            r"|\bignore[zr]?\s+(toutes\s+)?les\s+instructions\s+precedentes\b"
            r"|\bignoriere\s+(alle\s+)?(vorherigen|bisherigen)\s+anweisungen\b"
            r"|忽略(之前|以上|所有|先前)的?(指令|指示|说明|提示)")


# The rules that read a person's message and outside content in the same way.
# A free gap between the parts of a phrase ends at the end of a sentence or of a line.
# The space between two words that a rule names one after the other can be a line break.
_SHARED_RULES = _rules(
    # Wording that gives a model a role that has no rules.
    ("unrestricted_persona",
     r"\b(" + _ROLE + r"|from now on)\b[^.!?\n]{0,80}"
     r"\b(no|without|free of|free from|not bound by|unbound by)\s+((any|all)\s+)?"
     r"(restrictions|rules|limitations|filters|guidelines|ethics|morals|censorship|safeguards)\b"
     r"|\b(" + _ROLE + r"|simulate|stay in)\b[^.!?\n]{0,60}\b(developer|god|dan|jailbreak|jailbroken)\s+mode\b"
     r"|\b(" + _ROLE + r")\s+(now\s+)?an?\s+(unfiltered|uncensored|unrestricted|amoral|unethical)\b"
     r"|\b(dan|jailbreak|jailbroken)\s+mode\b"
     r"|\bdan\b[^\n]{0,200}\bdo anything now\b|\bdo anything now\b[^\n]{0,200}\bdan\b"),
    # Wording that tells a model to switch off its own protections.
    ("safeguard_removal",
     r"\b(disable|turn off|switch off|remove|deactivate|bypass|circumvent|get around|evade)\s+((all|any)\s+)?"
     r"(of\s+)?your\s+(own\s+)?(\w+\s+){0,2}"
     r"(filters?|safeguards?|guardrails?|restrictions|safety|censorship|limitations|moderation|content policy)\b"),
    # Wording that tells a model to follow instructions kept in an encoded form.
    ("encoded_instructions",
     r"\b(decode|decipher|decrypt|translate|unscramble)\b[^.\n]{0,80}\b" + _ENCODINGS + r"\b[^.\n]{0,80}"
     r"\b(follow|obey|execute|carry out|comply|do what it says)\b"
     r"|\b(follow|obey|execute|carry out)\b[^.\n]{0,40}\b" + _ENCODINGS + r"\b[^.\n]{0,20}"
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
_SINGLE_LETTERS = re.compile(r"\b([a-z] ){3,}[a-z]\b")
_TAG_RUN = re.compile("[\U000E0020-\U000E007E]+")
_SELECTOR_RUN = re.compile("[\uFE00-\uFE0F\U000E0100-\U000E01EF]{3,}")  # ordinary text has one selector after a character
_BASE64_RUN = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
_UNSEEN_RUN = 8  # a run of this many characters with no shape has the rule ``unseen_text``


class Finding(NamedTuple):
    rule: str
    excerpt: str  # the matched wording with a little of the text around it, for the person


def _forms(text: str) -> tuple[str, ...]:
    """The forms that ``text`` is read in. The plain form and the folded form come first."""
    forms: list[str] = []
    for source in dict.fromkeys((text, html.unescape(text))):
        base = unicodedata.normalize("NFKD", source)
        kinds = {ord(ch): unicodedata.category(ch) for ch in set(base)}
        marks = dict.fromkeys((point for point, kind in kinds.items() if kind == "Mn"))
        shapeless = [point for point, kind in kinds.items() if kind == "Cf"]
        for fill in (None, " ") if shapeless else (None,):  # a character with no shape is read as nothing, and as a space
            plain = _SPACING.sub(" ", base.translate(marks | dict.fromkeys(shapeless, fill)))
            lowered = plain.lower()
            for lower in dict.fromkeys((lowered, lowered.replace("1", "l"))):  # the digit 1 is read as i, and as l
                folded = lower.translate(_LOOK_ALIKES)
                forms += [plain, folded, _SINGLE_LETTERS.sub(lambda run: run.group().replace(" ", ""), folded)]
    return tuple(dict.fromkeys(forms))


def _selector_byte(selector: str) -> int:
    """The byte that one variation selector can carry."""
    point = ord(selector)
    return point - 0xFE00 if point <= 0xFE0F else point - 0xE0100 + 16


def _carried(text: str) -> list[tuple[str, bool]]:
    """Each text that the characters of ``text`` carry, and if its characters have no shape."""
    carried = [("".join(chr(ord(tag) - 0xE0000) for tag in run), True) for run in _TAG_RUN.findall(text)]
    for run in _SELECTOR_RUN.findall(text):
        codes = map(_selector_byte, run)
        carried.append(("".join(chr(code) if 32 <= code < 127 else " " for code in codes), True))
    for run in _BASE64_RUN.findall(text):
        try:
            decoded = base64.b64decode(run + "=" * (-len(run) % 4), validate=True).decode("ascii")
        except (binascii.Error, UnicodeDecodeError):
            continue  # the run is not text in base64, so it carries no text
        if " " in decoded and decoded.isprintable():
            carried.append((decoded, False))
    return carried


def _first(text: str, rules: tuple) -> Optional[Finding]:
    for form in _forms(text):
        for name, pattern in rules:
            match = pattern.search(form)
            if match:
                return Finding(name, form[max(0, match.start() - 60):match.end() + 60].strip())
    return None


def find_rule(text: str, *, content: bool = False) -> Optional[Finding]:
    """Return the first rule that ``text`` matches, or ``None``."""
    finding = _first(text, _CONTENT_RULES if content else _RULES)
    if finding:
        return finding
    carried = _carried(text)
    carried += [inner for part, _ in carried for inner in _carried(part)]
    for part, _ in carried:  # carried text is not the person's own wording
        finding = _first(part, _CONTENT_RULES)
        if finding:
            return finding
    unseen = next((part for part, shapeless in carried if shapeless and len(part) >= _UNSEEN_RUN), None)
    if unseen is None:
        return None
    return Finding("unseen_text", unseen.strip()[:120] or f"{len(unseen)} characters with no shape")
