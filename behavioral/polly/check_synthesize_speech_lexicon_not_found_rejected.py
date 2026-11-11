"""synthesize-speech-lexicon-not-found-rejected."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "synthesize-speech-lexicon-not-found-rejected"
GROUP = "overly-permissive"
SERVICES = ["polly"]

_PLS = """<?xml version="1.0" encoding="UTF-8"?>
<lexicon version="1.0" xmlns="http://www.w3.org/2005/01/pronunciation-lexicon"
    alphabet="ipa" xml:lang="en-US">
  <lexeme><grapheme>zz</grapheme><alias>zed zed</alias></lexeme>
</lexicon>
"""


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data", "resource:account-singleton:polly-lexicons")
def run(ctx) -> None:
    """SynthesizeSpeech naming a lexicon that was never stored fails with LexiconNotFoundException
    ('Lexicon not found'), while a request naming a stored lexicon returns audio."""
    polly = ctx.client("polly")
    missing_name = _lexicon_name(ctx, "missing")

    code, message = _error(
        lambda: polly.synthesize_speech(
            Text="Reference a lexicon that is not there.",
            OutputFormat="mp3",
            VoiceId="Joanna",
            LexiconNames=[missing_name],
        )
    )
    assert code == "LexiconNotFoundException", (
        f"expected LexiconNotFoundException, got {code!r}"
    )
    assert message == "Lexicon not found", message

    # positive control: a real, stored lexicon works
    real_name = _lexicon_name(ctx, "real")
    polly.put_lexicon(Name=real_name, Content=_PLS)
    ctx.on_cleanup(lambda: _safe_delete(polly, real_name))
    resp = polly.synthesize_speech(
        Text="Reference a lexicon that exists.",
        OutputFormat="mp3",
        VoiceId="Joanna",
        LexiconNames=[real_name],
    )
    audio = resp["AudioStream"].read()
    assert len(audio) > 1000, f"suspiciously small audio payload: {len(audio)} bytes"


def _lexicon_name(ctx: Any, tag: str = "") -> str:
    raw = ctx.unique_name(f"l{tag}")
    cleaned = "".join(c for c in raw if c.isalnum())
    return cleaned[:20] or f"lex{tag}"


def _safe_delete(polly, name: str) -> None:
    try:
        polly.delete_lexicon(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "LexiconNotFoundException":
            raise


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, call succeeded instead: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
