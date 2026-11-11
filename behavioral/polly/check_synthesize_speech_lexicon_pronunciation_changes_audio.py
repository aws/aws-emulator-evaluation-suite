"""synthesize-speech-lexicon-pronunciation-changes-audio."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "synthesize-speech-lexicon-pronunciation-changes-audio"
GROUP = "data-plane"
SERVICES = ["polly"]

_PLS = """<?xml version="1.0" encoding="UTF-8"?>
<lexicon version="1.0" xmlns="http://www.w3.org/2005/01/pronunciation-lexicon"
    alphabet="ipa" xml:lang="en-US">
  <lexeme><grapheme>AWS</grapheme><alias>Amazon Web Services</alias></lexeme>
</lexicon>
"""


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "dp:api", "plane:data", "resource:account-singleton:polly-lexicons")
def run(ctx) -> None:
    """A lexicon aliasing "AWS" to "Amazon Web Services" lengthens the PCM audio SynthesizeSpeech
    renders for the same text, so the lexicon is applied to synthesis."""
    polly = ctx.client("polly")
    name = _lexicon_name(ctx, "pr")
    polly.put_lexicon(Name=name, Content=_PLS)
    ctx.on_cleanup(lambda: _safe_delete(polly, name))

    text = "Please deploy AWS today."
    without = polly.synthesize_speech(Text=text, OutputFormat="pcm", VoiceId="Joanna")[
        "AudioStream"
    ].read()
    with_lexicon = polly.synthesize_speech(
        Text=text, OutputFormat="pcm", VoiceId="Joanna", LexiconNames=[name]
    )["AudioStream"].read()

    assert len(without) > 0 and len(with_lexicon) > 0, (
        f"expected non-empty PCM audio for both calls, got without={len(without)} with_lexicon={len(with_lexicon)}"
    )
    # "Amazon Web Services" (many more syllables) must render measurably
    # longer PCM audio than the bare "AWS" pronunciation.
    assert len(with_lexicon) > len(without) * 1.2, (
        f"without_lexicon={len(without)} with_lexicon={len(with_lexicon)}"
    )


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
