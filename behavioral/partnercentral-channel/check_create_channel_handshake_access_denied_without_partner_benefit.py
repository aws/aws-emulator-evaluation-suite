"""create-channel-handshake-access-denied-without-partner-benefit."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-channel-handshake-access-denied-without-partner-benefit"
GROUP = "overly-permissive"
SERVICES = ["partnercentral-channel"]

CATALOG = "Sandbox"
BENEFIT_DENIED = (
    "This action requires an active AWS Partner benefit. Register as an AWS Partner "
    "if you haven't already, or contact AWS Partner Central Support."
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateChannelHandshake naming a nonexistent associatedResourceIdentifier is refused with the
    exact entitlement AccessDeniedException (not ResourceNotFoundException) for a caller without an
    active AWS Partner benefit, identically on repeat."""
    client = ctx.client("partnercentral-channel")
    fake_pma_id = "pma-1111111111111"

    control = client.list_channel_handshakes(
        handshakeType="PROGRAM_MANAGEMENT_ACCOUNT",
        catalog=CATALOG,
        participantType="SENDER",
        maxResults=10,
    )
    assert isinstance(control.get("items"), list), control

    def _attempt():
        return client.create_channel_handshake(
            handshakeType="PROGRAM_MANAGEMENT_ACCOUNT",
            catalog=CATALOG,
            associatedResourceIdentifier=fake_pma_id,
        )

    code1, msg1 = _error_code(_attempt)
    assert code1 == "AccessDeniedException", f"expected AccessDeniedException, got {code1} ({msg1})"
    assert msg1 == BENEFIT_DENIED, msg1

    code2, msg2 = _error_code(_attempt)
    assert code2 == "AccessDeniedException", f"expected AccessDeniedException, got {code2} ({msg2})"
    assert msg2 == msg1, f"expected identical message on repeat, got {msg2!r} vs {msg1!r}"


def _error_code(fn):
    """Call fn(); return its botocore Error code and message. An unexpected SUCCESS raises,
    so a target that accepts a call real AWS denies cannot pass as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS denies this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
