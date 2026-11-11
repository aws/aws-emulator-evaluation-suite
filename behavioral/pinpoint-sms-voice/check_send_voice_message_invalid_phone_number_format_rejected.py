"""send-voice-message-invalid-phone-number-format-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "send-voice-message-invalid-phone-number-format-rejected"
GROUP = "overly-permissive"
SERVICES = ["pinpoint-sms-voice"]


def _send_error(client, destination):
    try:
        client.send_voice_message(
            DestinationPhoneNumber=destination,
            OriginationPhoneNumber="+12065550100",
            Content={"PlainTextMessage": {"Text": "sim2real behavioral probe", "VoiceId": "Joanna"}},
        )
        raise AssertionError(f"SendVoiceMessage unexpectedly succeeded for destination={destination!r}")
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SendVoiceMessage to a non-E.164 destination and to a well-formed one get the identical
    AccessDeniedException, so the denial precedes phone-number validation; ListConfigurationSets
    succeeds for the same caller."""
    client = ctx.client("pinpoint-sms-voice")

    # positive control: a read on the same service succeeds, so credentials are otherwise healthy
    client.list_configuration_sets()

    malformed_code, malformed_msg = _send_error(client, "not-a-phone-number")
    wellformed_code, wellformed_msg = _send_error(client, "+14255550182")

    assert malformed_code == "AccessDeniedException", (
        f"expected the account-level entitlement denial, got {malformed_code!r}: {malformed_msg!r}"
    )
    assert (wellformed_code, wellformed_msg) == (malformed_code, malformed_msg), (
        "a syntactically valid destination number got a DIFFERENT refusal "
        f"({wellformed_code!r}: {wellformed_msg!r}) than the malformed one "
        f"({malformed_code!r}: {malformed_msg!r}) -- the denial is supposed to be input-"
        "independent; if it now varies by input, SendVoiceMessage may be enforcing phone-"
        "number validation again and this check needs rewriting back to that contract"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
