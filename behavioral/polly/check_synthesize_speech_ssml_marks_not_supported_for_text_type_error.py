"""synthesize-speech-ssml-marks-not-supported-for-text-type-error."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "synthesize-speech-ssml-marks-not-supported-for-text-type-error"
GROUP = "error-semantics"
SERVICES = ["polly"]


@tags("axis:rejection", "cap:unclassified", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Requesting ssml speech marks with TextType=text fails with
    SsmlMarksNotSupportedForTextTypeException, while the same request with TextType=ssml returns
    marks."""
    polly = ctx.client("polly")

    code, message = _error_code(
        lambda: polly.synthesize_speech(
            Text="Hello there.",
            TextType="text",
            OutputFormat="json",
            VoiceId="Joanna",
            SpeechMarkTypes=["ssml"],
        )
    )
    assert code == "SsmlMarksNotSupportedForTextTypeException", code
    assert message == "SSML Speech marks are not supported for this text type", message

    resp = polly.synthesize_speech(
        Text='<speak>Hello <mark name="here"/>there.</speak>',
        TextType="ssml",
        OutputFormat="json",
        VoiceId="Joanna",
        SpeechMarkTypes=["ssml"],
    )
    assert resp["ContentType"] == "application/x-json-stream"
    body = resp["AudioStream"].read()
    assert len(body) > 0
    assert b'"type":"ssml"' in body or b'"type": "ssml"' in body


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
