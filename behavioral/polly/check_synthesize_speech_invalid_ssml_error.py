"""synthesize-speech-invalid-ssml-error."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "synthesize-speech-invalid-ssml-error"
GROUP = "error-semantics"
SERVICES = ["polly"]


@tags("axis:rejection", "cap:unclassified", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SynthesizeSpeech with TextType=ssml and malformed markup raises InvalidSsmlException,
    while the same markup fixed to be well-formed synthesizes successfully."""
    polly = ctx.client("polly")
    broken_ssml = "<speak>This tag is never closed properly"

    error = _error(
        lambda: polly.synthesize_speech(
            Text=broken_ssml,
            TextType="ssml",
            OutputFormat="mp3",
            VoiceId="Joanna",
        )
    )
    code, message = error.get("Code"), error.get("Message")
    assert code == "InvalidSsmlException", code
    assert message == "Invalid SSML request", f"expected the exact invalid-SSML message, got {message!r}"

    valid_ssml = "<speak>This tag is closed properly.</speak>"
    resp = polly.synthesize_speech(
        Text=valid_ssml, TextType="ssml", OutputFormat="mp3", VoiceId="Joanna"
    )
    assert resp["ContentType"] == "audio/mpeg", resp["ContentType"]
    audio = resp["AudioStream"].read()
    assert len(audio) > 0, len(audio)


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
