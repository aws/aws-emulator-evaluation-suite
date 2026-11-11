"""synthesize-speech-multiple-lexicons-combined."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "synthesize-speech-multiple-lexicons-combined"
GROUP = "data-plane"
SERVICES = ["polly"]


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "dp:api", "plane:data", "resource:account-singleton:polly-lexicons")
def run(ctx) -> None:
    """SynthesizeSpeech with two LexiconNames applies both: the PCM audio is longer than with
    either lexicon alone."""
    polly = ctx.client("polly")
    name_a = _lexicon_name(ctx, "lexA")
    name_b = _lexicon_name(ctx, "lexB")
    polly.put_lexicon(Name=name_a, Content=_pls([("AWS", "Amazon Web Services")]))
    ctx.on_cleanup(lambda: _safe_delete_lexicon(polly, name_a))
    polly.put_lexicon(Name=name_b, Content=_pls([("S3", "Simple Storage Service")]))
    ctx.on_cleanup(lambda: _safe_delete_lexicon(polly, name_b))

    text = "AWS S3 stores objects reliably."
    baseline = _synthesize_pcm(polly, text, [])
    only_a = _synthesize_pcm(polly, text, [name_a])
    only_b = _synthesize_pcm(polly, text, [name_b])
    combined = _synthesize_pcm(polly, text, [name_a, name_b])

    assert len(baseline) > 0, "baseline synthesis produced no audio"
    assert len(only_a) > len(baseline), (
        f"lexicon {name_a!r} alone must lengthen audio: baseline={len(baseline)} only_a={len(only_a)}"
    )
    assert len(only_b) > len(baseline), (
        f"lexicon {name_b!r} alone must lengthen audio: baseline={len(baseline)} only_b={len(only_b)}"
    )
    # the decisive claim: BOTH lexicons applied together must render strictly
    # longer audio than either one applied alone -- a target that only consults
    # the first (or only one) LexiconNames entry fails exactly this comparison.
    assert len(combined) > len(only_a), (
        f"combined must exceed lexicon {name_a!r} alone: combined={len(combined)} only_a={len(only_a)}"
    )
    assert len(combined) > len(only_b), (
        f"combined must exceed lexicon {name_b!r} alone: combined={len(combined)} only_b={len(only_b)}"
    )

    # sanity: the requested output format is still honored when both lexicons are applied
    resp = polly.synthesize_speech(
        Text=text, OutputFormat="mp3", VoiceId="Joanna", LexiconNames=[name_a, name_b]
    )
    assert resp["ContentType"] == "audio/mpeg", resp["ContentType"]


def _synthesize_pcm(polly, text: str, lexicon_names: list) -> bytes:
    kwargs = {"Text": text, "OutputFormat": "pcm", "VoiceId": "Joanna"}
    if lexicon_names:
        kwargs["LexiconNames"] = lexicon_names
    return polly.synthesize_speech(**kwargs)["AudioStream"].read()


def _lexicon_name(ctx, tag: str) -> str:
    # Lexicon names are [0-9A-Za-z]{1,20}; "sim2real" (8) + the 12-hex unique suffix is exactly 20,
    # so `tag` does not fit without truncating the random suffix. It stays a call-site label only.
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
