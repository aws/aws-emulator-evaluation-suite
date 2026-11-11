"""put-get-lexicon-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-get-lexicon-round-trip"
GROUP = "state"
SERVICES = ["polly"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:polly-lexicons")
def run(ctx) -> None:
    """PutLexicon persists exact PLS content and GetLexicon returns it verbatim along with
    accurate derived attributes (alphabet, language, lexeme count, size)."""
    polly = ctx.client("polly")
    name = _lexicon_name(ctx, "rt")
    content = _pls([("AWS", "Amazon Web Services")])

    polly.put_lexicon(Name=name, Content=content)
    ctx.on_cleanup(lambda: _safe_delete_lexicon(polly, name))

    got = polly.get_lexicon(Name=name)
    assert got["Lexicon"]["Name"] == name, (
        f"expected GetLexicon to echo Name={name!r}, got {got['Lexicon'].get('Name')!r}"
    )
    assert got["Lexicon"]["Content"] == content, (
        f"expected GetLexicon Content to match what was PUT verbatim; "
        f"got {got['Lexicon'].get('Content')!r}"
    )

    attrs = got["LexiconAttributes"]
    assert attrs["LanguageCode"] == "en-US", f"expected LanguageCode=en-US, got {attrs}"
    assert attrs["Alphabet"] == "ipa", f"expected Alphabet=ipa, got {attrs}"
    assert attrs["LexemesCount"] == 1, f"expected LexemesCount=1, got {attrs}"
    assert attrs["Size"] == len(content), (
        f"expected Size=len(content)={len(content)}, got {attrs}"
    )


def _lexicon_name(ctx, tag: str) -> str:
    # Lexicon names are [0-9A-Za-z]{1,20}; "sim2real" (8) + the 12-hex unique suffix is exactly 20,
    # so `tag` no longer fits without truncating the random suffix. It stays a call-site label only.
    raw = ctx.unique_name("sim2real")
    return "".join(ch for ch in raw if ch.isalnum())[:20]


def _pls(entries, lang: str = "en-US", alphabet: str = "ipa") -> str:
    body = "".join(
        f"<lexeme><grapheme>{g}</grapheme><alias>{a}</alias></lexeme>"
        for g, a in entries
    )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<lexicon version="1.0" xmlns="http://www.w3.org/2005/01/pronunciation-lexicon" '
        f'alphabet="{alphabet}" xml:lang="{lang}">{body}</lexicon>'
    )


def _safe_delete_lexicon(polly, name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        polly.delete_lexicon(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "LexiconNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
