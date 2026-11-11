"""synthesize-speech-engine-not-supported-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "synthesize-speech-engine-not-supported-rejected"
GROUP = "overly-permissive"
SERVICES = ["polly"]


@tags("axis:rejection", "cap:unclassified", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SynthesizeSpeech with the neural engine for a standard-only voice (Geraint) fails with
    ValidationException, while the same voice on the standard engine synthesizes audio."""
    polly = ctx.client("polly")
    text = "Testing engine compatibility validation."

    code, message = _error(
        lambda: polly.synthesize_speech(
            Text=text, OutputFormat="mp3", VoiceId="Geraint", Engine="neural"
        )
    )
    assert code == "ValidationException", code
    assert message == "This voice does not support the selected engine: neural", message


    resp = polly.synthesize_speech(
        Text=text, OutputFormat="mp3", VoiceId="Geraint", Engine="standard"
    )
    assert resp["ContentType"] == "audio/mpeg", resp.get("ContentType")
    audio = resp["AudioStream"].read()
    assert len(audio) > 0, f"expected non-empty mp3 audio, got {len(audio)} bytes"


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
