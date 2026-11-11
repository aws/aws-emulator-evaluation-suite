"""put-lexicon-size-exceeded-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-lexicon-size-exceeded-rejected"
GROUP = "overly-permissive"
SERVICES = ["polly"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:polly-lexicons")
def run(ctx) -> None:
    """PutLexicon rejects a PLS document larger than the documented 40,000-character lexicon
    size limit with LexiconSizeExceededException and never stores it, while a small, valid
    lexicon still succeeds."""
    polly = ctx.client("polly")
    oversized_name = _lexicon_name(ctx, "big")
    oversized_content = _oversized_pls(min_size=40001)
    assert len(oversized_content) > 40000, len(oversized_content)

    code, message = _error_code(
        lambda: polly.put_lexicon(Name=oversized_name, Content=oversized_content)
    )
    assert code == "LexiconSizeExceededException", code
    assert message == "Maximum lexicons size has been exceeded", message

    lookup_code, lookup_message = _error_code(lambda: polly.get_lexicon(Name=oversized_name))
    assert lookup_code == "LexiconNotFoundException", lookup_code
    assert lookup_message == "Lexicon not found", lookup_message

    # Positive control: a small, well-formed lexicon is unaffected by the size boundary.
    small_name = _lexicon_name(ctx, "small")
    small_content = _pls([("ok", "okay")])
    polly.put_lexicon(Name=small_name, Content=small_content)
    ctx.on_cleanup(lambda: _safe_delete_lexicon(polly, small_name))
    got = polly.get_lexicon(Name=small_name)
    assert got["Lexicon"]["Content"] == small_content, got["Lexicon"]["Content"]


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


def _oversized_pls(min_size: int) -> str:
    entries = []
    i = 0
    while True:
        entries.append((f"word{i}", f"alias number {i} padding text"))
        content = _pls(entries)
        if len(content) > min_size:
            return content
        i += 1


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
