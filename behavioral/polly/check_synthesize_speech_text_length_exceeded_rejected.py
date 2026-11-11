"""synthesize-speech-text-length-exceeded-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "synthesize-speech-text-length-exceeded-rejected"
GROUP = "overly-permissive"
SERVICES = ["polly"]


@tags("axis:rejection", "cap:unclassified", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SynthesizeSpeech rejects plain text over the documented 3000 billed-character real-time
    limit with TextLengthExceededException and returns no audio, while the same text trimmed
    under the limit synthesizes successfully."""
    polly = ctx.client("polly")
    too_long_text = "a" * 3001
    within_limit_text = "a" * 100

    code, message = _error(
        lambda: polly.synthesize_speech(
            Text=too_long_text, OutputFormat="mp3", VoiceId="Joanna"
        )
    )
    assert code == "TextLengthExceededException", code
    assert message == "Maximum text length has been exceeded", message

    resp = polly.synthesize_speech(
        Text=within_limit_text, OutputFormat="mp3", VoiceId="Joanna"
    )
    assert resp["ContentType"] == "audio/mpeg", resp.get("ContentType")
    assert resp["RequestCharacters"] == len(within_limit_text), (
        resp.get("RequestCharacters"),
        len(within_limit_text),
    )
    audio_bytes = resp["AudioStream"].read()
    assert len(audio_bytes) > 0, len(audio_bytes)


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
