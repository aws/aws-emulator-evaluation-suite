"""put-lexicon-unsupported-alphabet-error."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-lexicon-unsupported-alphabet-error"
GROUP = "error-semantics"
SERVICES = ["polly"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:polly-lexicons")
def run(ctx) -> None:
    """PutLexicon with an unrecognized PLS alphabet fails with InvalidLexiconException and stores
    nothing, while the same alias-only document with a supported alphabet is stored."""
    polly = ctx.client("polly")
    bad_name = _lexicon_name(ctx, "alph")
    good_name = _lexicon_name(ctx, "alphok")

    ctx.on_cleanup(lambda: _safe_delete_lexicon(polly, bad_name))
    bad_content = _pls_alias([("word", "wurd")], alphabet="klingon")
    code, message = _error_code(lambda: polly.put_lexicon(Name=bad_name, Content=bad_content))
    assert code == "InvalidLexiconException", code
    assert message == "Invalid PLS Lexicon", message

    lookup_code, lookup_message = _error_code(lambda: polly.get_lexicon(Name=bad_name))
    assert lookup_code == "LexiconNotFoundException", lookup_code
    assert lookup_message == "Lexicon not found", lookup_message

    good_content = _pls([("word", "wɜːd")], alphabet="ipa")
    polly.put_lexicon(Name=good_name, Content=good_content)
    ctx.on_cleanup(lambda: _safe_delete_lexicon(polly, good_name))
    got = polly.get_lexicon(Name=good_name)
    alphabet = got["LexiconAttributes"]["Alphabet"]
    assert alphabet == "ipa", f"expected Alphabet='ipa', got {alphabet!r}"


def _lexicon_name(ctx, tag: str) -> str:
    # Lexicon names are [0-9A-Za-z]{1,20}; "sim2real" (8) + the 12-hex unique suffix is exactly 20,
    # so `tag` does not fit without truncating the random suffix. It stays a call-site label only.
    raw = ctx.unique_name("sim2real")
    return "".join(ch for ch in raw if ch.isalnum())[:20]


def _pls_alias(entries, lang: str = "en-US", alphabet: str = "ipa") -> str:
    body = "".join(
        f"<lexeme><grapheme>{g}</grapheme><alias>{a}</alias></lexeme>"
        for g, a in entries
    )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<lexicon version="1.0" xmlns="http://www.w3.org/2005/01/pronunciation-lexicon" '
        f'alphabet="{alphabet}" xml:lang="{lang}">{body}</lexicon>'
    )


def _pls(entries, lang: str = "en-US", alphabet: str = "ipa") -> str:
    body = "".join(
        f"<lexeme><grapheme>{g}</grapheme><phoneme>{a}</phoneme></lexeme>"
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
