"""synthesize-speech-invalid-sample-rate-error."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "synthesize-speech-invalid-sample-rate-error"
GROUP = "error-semantics"
SERVICES = ["polly"]


@tags("axis:rejection", "cap:unclassified", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SynthesizeSpeech with a SampleRate outside the documented valid set for mp3
    ("8000"/"16000"/"22050"/"24000"/"44100"/"48000") raises InvalidSampleRateException,
    while a documented valid sample rate succeeds."""
    polly = ctx.client("polly")
    text = "Testing sample rate validation."

    code, message = _error_code(
        lambda: polly.synthesize_speech(
            Text=text, OutputFormat="mp3", VoiceId="Joanna", SampleRate="99999"
        )
    )
    assert code == "InvalidSampleRateException", (
        f"expected InvalidSampleRateException, got {code!r}"
    )
    assert message == "Invalid SampleRate parameter", message

    resp = polly.synthesize_speech(
        Text=text, OutputFormat="mp3", VoiceId="Joanna", SampleRate="22050"
    )
    assert resp["ContentType"] == "audio/mpeg", (
        f"expected audio/mpeg, got {resp['ContentType']!r}"
    )
    audio = resp["AudioStream"].read()
    assert len(audio) > 0, f"expected non-empty audio for a valid SampleRate, got {len(audio)} bytes"


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
