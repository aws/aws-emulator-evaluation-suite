"""reject-channel-handshake-nonexistent-error."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "reject-channel-handshake-nonexistent-error"
GROUP = "overly-permissive"
SERVICES = ["partnercentral-channel"]

CATALOG = "Sandbox"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RejectChannelHandshake on a well-formed nonexistent handshake is refused with
    AccessDeniedException whose message names the resource-based policy and the action, identically on
    repeat; ListChannelHandshakes succeeds for the same caller."""
    client = ctx.client("partnercentral-channel")
    fake_hs_id = "ch-1111111111111"

    resp = client.list_channel_handshakes(
        handshakeType="PROGRAM_MANAGEMENT_ACCOUNT",
        catalog=CATALOG,
        participantType="SENDER",
        maxResults=10,
    )
    assert isinstance(resp.get("items"), list), resp

    def _attempt():
        return client.reject_channel_handshake(catalog=CATALOG, identifier=fake_hs_id)

    code1, msg1 = _error_code(_attempt)
    assert code1 == "AccessDeniedException", f"expected AccessDeniedException, got {code1}: {msg1}"
    assert msg1 and "resource-based policy" in msg1 and "RejectChannelHandshake" in msg1, msg1

    code2, msg2 = _error_code(_attempt)
    assert code2 == code1, f"expected identical denial on retry, got {code2}"
    assert msg2 == msg1, "expected an identical message on retry; the IAM gate must be deterministic"


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected reject_channel_handshake to be denied, but it SUCCEEDED: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
