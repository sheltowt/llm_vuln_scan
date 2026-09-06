"""Encoding and obfuscation converters.

These are the cheap deterministic half of the attack surface: no attacker model,
no nondeterminism, safe to run on every pull request.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
import unicodedata

from ..core.plugin import register
from .base import Converter

_B64_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_HEX_RE = re.compile(r"(?:[0-9a-fA-F]{2}\s*){8,}")


@register("converter", "identity")
class IdentityConverter(Converter):
    reversible = True

    def transform(self, text: str) -> str:
        return text


@register("converter", "base64")
class Base64Converter(Converter):
    reversible = True

    def transform(self, text: str) -> str:
        return base64.b64encode(text.encode("utf-8")).decode("ascii")

    def untransform(self, text: str) -> str:
        """Decode any base64 blob the model echoed back, appending the plaintext.

        We append rather than replace so string detectors still see the original
        response; a model that answers in base64 must not evade scoring.
        """
        decoded: list[str] = []
        for match in _B64_RE.findall(text):
            try:
                candidate = base64.b64decode(match + "=" * (-len(match) % 4), validate=True)
                as_text = candidate.decode("utf-8")
            except (binascii.Error, UnicodeDecodeError, ValueError):
                continue
            if as_text.isprintable() and len(as_text) > 8:
                decoded.append(as_text)
        return text + ("\n\n[decoded]\n" + "\n".join(decoded) if decoded else "")


@register("converter", "hex")
class HexConverter(Converter):
    reversible = True

    def transform(self, text: str) -> str:
        return " ".join(f"{b:02x}" for b in text.encode("utf-8"))

    def untransform(self, text: str) -> str:
        decoded: list[str] = []
        for match in _HEX_RE.findall(text):
            try:
                as_text = bytes.fromhex(match.replace(" ", "")).decode("utf-8")
            except (ValueError, UnicodeDecodeError):
                continue
            if as_text.isprintable() and len(as_text) > 8:
                decoded.append(as_text)
        return text + ("\n\n[decoded]\n" + "\n".join(decoded) if decoded else "")


@register("converter", "rot13")
class Rot13Converter(Converter):
    reversible = True

    def transform(self, text: str) -> str:
        return codecs.encode(text, "rot_13")

    def untransform(self, text: str) -> str:
        return text + "\n\n[decoded]\n" + codecs.encode(text, "rot_13")


_LEET = str.maketrans({"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7", "l": "1"})


@register("converter", "leetspeak")
class LeetspeakConverter(Converter):
    def transform(self, text: str) -> str:
        return text.translate(_LEET)


_HOMOGLYPHS = {
    "a": "а", "c": "с", "e": "е", "i": "і", "j": "ј",
    "o": "о", "p": "р", "s": "ѕ", "x": "х", "y": "у",
}


@register("converter", "homoglyph")
class HomoglyphConverter(Converter):
    """Swap Latin letters for visually identical Cyrillic ones.

    Defeats naive keyword filters while remaining readable to the model.
    """

    DEFAULT_PARAMS = {"rate": 0.6}

    def transform(self, text: str) -> str:
        out = []
        for index, ch in enumerate(text):
            swap = _HOMOGLYPHS.get(ch.lower())
            if swap and (index % 3) < max(1, int(3 * float(self.params["rate"]))):
                out.append(swap if ch.islower() else swap.upper())
            else:
                out.append(ch)
        return "".join(out)

    def untransform(self, text: str) -> str:
        return unicodedata.normalize("NFKC", text)


@register("converter", "zero_width")
class ZeroWidthConverter(Converter):
    """Insert zero-width joiners inside trigger words to split tokenizer matches."""

    DEFAULT_PARAMS = {"every": 3, "char": "​"}

    def transform(self, text: str) -> str:
        every = max(1, int(self.params["every"]))
        char = str(self.params["char"])
        return char.join(text[i : i + every] for i in range(0, len(text), every))

    def untransform(self, text: str) -> str:
        return re.sub(r"[​-‏⁠﻿]", "", text)


_MORSE = {
    "a": ".-", "b": "-...", "c": "-.-.", "d": "-..", "e": ".", "f": "..-.", "g": "--.",
    "h": "....", "i": "..", "j": ".---", "k": "-.-", "l": ".-..", "m": "--", "n": "-.",
    "o": "---", "p": ".--.", "q": "--.-", "r": ".-.", "s": "...", "t": "-", "u": "..-",
    "v": "...-", "w": ".--", "x": "-..-", "y": "-.--", "z": "--..", "0": "-----",
    "1": ".----", "2": "..---", "3": "...--", "4": "....-", "5": ".....", "6": "-....",
    "7": "--...", "8": "---..", "9": "----.", ".": ".-.-.-", ",": "--..--", "?": "..--..",
}


@register("converter", "morse")
class MorseConverter(Converter):
    def transform(self, text: str) -> str:
        return " / ".join(
            " ".join(_MORSE.get(ch, "") for ch in word.lower() if ch in _MORSE)
            for word in text.split()
        )


@register("converter", "reverse")
class ReverseConverter(Converter):
    """Character reversal, the basis of the FlipAttack family."""

    reversible = True

    def transform(self, text: str) -> str:
        return text[::-1]

    def untransform(self, text: str) -> str:
        return text + "\n\n[decoded]\n" + text[::-1]


@register("converter", "upper")
class UpperConverter(Converter):
    def transform(self, text: str) -> str:
        return text.upper()


# Unicode Tags block (U+E0000..U+E007F) mirrors ASCII but renders invisibly in
# most clients. Text encoded here is unreadable to a human reviewer yet many
# models still decode and act on it: the "ASCII smuggling" / invisible-injection
# class. TAG_BASE + ord(ch) maps a printable ASCII char to its tag twin.
_TAG_BASE = 0xE0000


@register("converter", "ascii_smuggling")
class AsciiSmugglingConverter(Converter):
    """Encode the payload in invisible Unicode tag characters.

    The transformed text looks empty (or like the optional visible cover) to a
    human, so this tests whether the target decodes and obeys content its own
    operators cannot see.
    """

    reversible = True
    DEFAULT_PARAMS = {"cover": ""}

    def transform(self, text: str) -> str:
        smuggled = "".join(
            chr(_TAG_BASE + ord(ch)) if 0x20 <= ord(ch) <= 0x7E else ch for ch in text
        )
        return f"{self.params['cover']}{smuggled}" if self.params.get("cover") else smuggled

    def untransform(self, text: str) -> str:
        # Decode any tag-encoded run the model echoed back, so scoring sees it.
        decoded = "".join(
            chr(ord(ch) - _TAG_BASE) if _TAG_BASE <= ord(ch) <= _TAG_BASE + 0x7F else ch
            for ch in text
        )
        return decoded if decoded != text else text
