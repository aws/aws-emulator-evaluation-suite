"""synthesize-speech-marks-not-supported-for-format-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "synthesize-speech-marks-not-supported-for-format-rejected"
GROUP = "overly-permissive"
SERVICES = ["polly"]


@tags("axis:rejection", "cap:unclassified", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SynthesizeSpeech with SpeechMarkTypes and OutputFormat=mp3 fails with
    MarksNotSupportedForFormatException, while OutputFormat=json returns per-word speech marks."""
    polly = ctx.client("polly")
    text = "Mark this word."

    code, message = _error(
        lambda: polly.synthesize_speech(
            Text=text,
            OutputFormat="mp3",
            VoiceId="Joanna",
            SpeechMarkTypes=["word"],
        )
    )
    assert code == "MarksNotSupportedForFormatException", code
    assert message == "Speech marks are not supported for this format", message

    # positive control: the identical marks request against json output succeeds
    # and returns marks describing each word, not a stub echo of the input.
    resp = polly.synthesize_speech(
        Text=text,
        OutputFormat="json",
        VoiceId="Joanna",
        SpeechMarkTypes=["word"],
    )
    assert resp["ContentType"] == "application/x-json-stream", resp.get("ContentType")
    raw = resp["AudioStream"].read().decode("utf-8")
    lines = [line for line in raw.splitlines() if line.strip()]
    marks = [json.loads(line) for line in lines]
    assert marks, f"expected non-empty speech marks for {text!r}"
    for mark in marks:
        assert mark["type"] == "word", mark
    values = [m["value"] for m in marks]
    assert values == ["Mark", "this", "word"], values
    times = [m["time"] for m in marks]
    assert times == sorted(times), times


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
