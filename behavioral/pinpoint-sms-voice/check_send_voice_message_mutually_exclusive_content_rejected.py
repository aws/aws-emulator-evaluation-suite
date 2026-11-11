"""send-voice-message-mutually-exclusive-content-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "send-voice-message-mutually-exclusive-content-rejected"
GROUP = "overly-permissive"
SERVICES = ["pinpoint-sms-voice"]


def _error_code(fn, what: str) -> tuple[str, str | None]:
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"{what} unexpectedly succeeded")


@tags("axis:rejection", "cap:unclassified", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SendVoiceMessage with both PlainTextMessage and SSMLMessage gets BadRequestException with its
    exact message, while the same request with one content type gets AccessDeniedException "Access
    Denied"."""
    client = ctx.client("pinpoint-sms-voice")
    destination = "+12065550199"
    origination = "+12065550100"

    single_code, single_message = _error_code(
        lambda: client.send_voice_message(
            DestinationPhoneNumber=destination,
            OriginationPhoneNumber=origination,
            Content={"PlainTextMessage": {"Text": "sim2real behavioral probe", "VoiceId": "Joanna"}},
        ),
        "the well-formed single-content-type control call",
    )
    assert single_code == "AccessDeniedException", (
        f"expected the well-formed single-content-type call to fail only on number "
        f"entitlement with these unprovisioned numbers, got {single_code!r}"
    )
    assert single_message == "Access Denied", f"expected the message 'Access Denied', got {single_message!r}"

    multi_code, multi_message = _error_code(
        lambda: client.send_voice_message(
            DestinationPhoneNumber=destination,
            OriginationPhoneNumber=origination,
            Content={
                "PlainTextMessage": {"Text": "sim2real behavioral probe", "VoiceId": "Joanna"},
                "SSMLMessage": {"Text": "<speak>sim2real behavioral probe</speak>", "VoiceId": "Joanna"},
            },
        ),
        "the mutually-exclusive two-content-type call",
    )
    assert multi_code == "BadRequestException", (
        f"expected a content-validation rejection for two content types at once, got {multi_code!r}"
    )
    expected = "Message is invalid. The message must have either a plain text, SSML, or call instructions message"
    assert multi_message == expected, f"expected message {expected!r}, got {multi_message!r}"
    assert multi_code != single_code, (
        "the ambiguous-content call must be rejected on a different, more specific code "
        "than the entitlement failure -- not folded into the same blanket denial"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
