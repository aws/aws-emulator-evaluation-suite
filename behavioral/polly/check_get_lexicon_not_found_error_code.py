"""get-lexicon-not-found-error-code."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-lexicon-not-found-error-code"
GROUP = "error-semantics"
SERVICES = ["polly"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:polly-lexicons")
def run(ctx) -> None:
    """GetLexicon on a name that was never stored raises LexiconNotFoundException, while an
    existing lexicon in the same account remains fully retrievable."""
    polly = ctx.client("polly")
    good_name = _lexicon_name(ctx, "good")
    content = _pls([("ok", "okay")])
    polly.put_lexicon(Name=good_name, Content=content)
    ctx.on_cleanup(lambda: _safe_delete_lexicon(polly, good_name))

    missing_name = _lexicon_name(ctx, "gone")
    code, message = _error_code(lambda: polly.get_lexicon(Name=missing_name))
    assert code == "LexiconNotFoundException", (
        f"expected LexiconNotFoundException for never-stored {missing_name!r}, got {code!r}"
    )
    assert message == "Lexicon not found", message

    # Positive control: the sibling lexicon is unaffected by the failed lookup.
    got = polly.get_lexicon(Name=good_name)
    assert got["Lexicon"]["Content"] == content, (
        f"expected {good_name!r} content {content!r}, got {got['Lexicon']['Content']!r}"
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


def _error_code(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
