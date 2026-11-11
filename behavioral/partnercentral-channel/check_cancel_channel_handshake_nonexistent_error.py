"""cancel-channel-handshake-nonexistent-error."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "cancel-channel-handshake-nonexistent-error"
GROUP = "overly-permissive"
SERVICES = ["partnercentral-channel"]

CATALOG = "Sandbox"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CancelChannelHandshake on a well-formed nonexistent handshake identifier is refused with
    AccessDeniedException and its exact message, so the caller learns nothing about the target;
    ListChannelHandshakes succeeds for the same caller."""
    client = ctx.client("partnercentral-channel")

    control = client.list_channel_handshakes(
        handshakeType="PROGRAM_MANAGEMENT_ACCOUNT",
        catalog=CATALOG,
        participantType="SENDER",
        maxResults=10,
    )
    assert isinstance(control.get("items"), list), control

    fake_hs_id = "ch-1111111111111"

    def _attempt():
        client.cancel_channel_handshake(catalog=CATALOG, identifier=fake_hs_id)

    code, message = _error_code(_attempt)
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code}"
    # The denial is an IAM authorization message that names the calling principal, so the
    # expected text is built from the caller's own identity.
    caller_arn = ctx.client("sts").get_caller_identity()["Arn"]
    expected = (
        f"User: {caller_arn} is not authorized to perform: partnercentral:CancelChannelHandshake "
        f"on resource: {fake_hs_id} because no identity-based policy allows the "
        "partnercentral:CancelChannelHandshake action"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"


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
