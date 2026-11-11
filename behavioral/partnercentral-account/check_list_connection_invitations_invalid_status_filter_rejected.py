"""list-connection-invitations-invalid-status-filter-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-connection-invitations-invalid-status-filter-rejected"
GROUP = "overly-permissive"
SERVICES = ["partnercentral-account"]


def _pca_client(ctx):
    """partnercentral-account is only served from us-east-1, so pin the region."""
    return ctx.client("partnercentral-account", region="us-east-1")


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its ClientError code and message. An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListConnectionInvitations rejects a Status filter value outside the modeled
    InvitationStatus enum with ValidationException, while the identical call with a valid
    Status filter succeeds and returns a well-formed (possibly empty) list."""
    pca = _pca_client(ctx)

    code, message = _error(
        lambda: pca.list_connection_invitations(Catalog="AWS", Status="NOT_A_REAL_STATUS")
    )
    assert code == "ValidationException", (
        f"Status='NOT_A_REAL_STATUS' (outside the InvitationStatus enum) was rejected with "
        f"{code!r}, expected 'ValidationException'"
    )
    expected = (
        "1 validation error detected: Value at 'status' failed to satisfy constraint: "
        "Member must satisfy enum value set: [EXPIRED, ACCEPTED, PENDING, CANCELED, REJECTED]"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control: the identical call shape with a valid Status filter succeeds.
    resp = pca.list_connection_invitations(Catalog="AWS", Status="PENDING")
    summaries = resp["ConnectionInvitationSummaries"]
    assert isinstance(summaries, list), (
        f"ListConnectionInvitations(Status='PENDING') returned "
        f"{summaries!r}, expected a list"
    )
    for summary in summaries:
        assert summary["Status"] == "PENDING", (
            f"ListConnectionInvitations(Status='PENDING') returned a summary with "
            f"Status={summary['Status']!r}, expected 'PENDING'"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
