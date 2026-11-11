"""list-channel-handshakes-maxresults-out-of-range-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-channel-handshakes-maxresults-out-of-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["partnercentral-channel"]

CATALOG = "Sandbox"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListChannelHandshakes rejects maxResults above the documented [1,100] range
    with ValidationException and returns no page, while a valid maxResults for the same
    required filters succeeds (this List call is reachable without partner benefit)."""
    client = ctx.client("partnercentral-channel")

    captured = {}

    def _attempt_out_of_range():
        captured["resp"] = client.list_channel_handshakes(
            handshakeType="PROGRAM_MANAGEMENT_ACCOUNT",
            catalog=CATALOG,
            participantType="SENDER",
            maxResults=1000,
        )

    rejected = _error(_attempt_out_of_range)
    code = rejected["Error"]["Code"]
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    assert rejected["Error"].get("Message") == "1 validation error detected.", rejected
    assert rejected.get("fieldList") == [
        {
            "name": "maxResults",
            "code": "INVALID_VALUE",
            "message": "Value at 'maxResults' failed to satisfy constraint: "
            "Member must have value less than or equal to 100",
        }
    ], f"fieldList={rejected.get('fieldList')!r}"
    assert "resp" not in captured, (
        f"expected the out-of-range call to raise before returning a page, got {captured.get('resp')!r}"
    )

    resp = client.list_channel_handshakes(
        handshakeType="PROGRAM_MANAGEMENT_ACCOUNT",
        catalog=CATALOG,
        participantType="SENDER",
        maxResults=50,
    )
    assert isinstance(resp.get("items"), list), (
        f"expected a well-shaped page for an in-range maxResults, got items={resp.get('items')!r}"
    )


def _error(fn):
    """Call fn(); return its botocore response dict (Code/Message under "Error", modeled
    error members such as fieldList at the top level). An unexpected SUCCESS raises, so a
    target that accepts input real AWS refuses cannot pass as an error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
