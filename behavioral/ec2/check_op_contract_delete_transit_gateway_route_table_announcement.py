"""op-contract-deleteTransitGatewayRouteTableAnnouncement."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deleteTransitGatewayRouteTableAnnouncement"
GROUP = "error-semantics"
SERVICES = ["ec2"]

#: Well-formed (correct prefix, 17-hex-char suffix) and never created in any account.
_ABSENT_ANNOUNCEMENT_ID = "tgw-rtb-announce-0123456789abcdef0"
#: Same operation, an id that does not even parse.
_MALFORMED_ANNOUNCEMENT_ID = "not-an-id"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteTransitGatewayRouteTableAnnouncement fails an absent well-formed ID with
    InvalidTransitGatewayRouteTableAnnouncementId.NotFound and an unparseable one with the .Malformed
    code; DryRun on the absent ID answers DryRunOperation, and describe still reports it not found."""
    ec2 = ctx.client("ec2")

    absent, _ = _error_code(
        lambda: ec2.delete_transit_gateway_route_table_announcement(
            TransitGatewayRouteTableAnnouncementId=_ABSENT_ANNOUNCEMENT_ID
        )
    )
    assert absent == "InvalidTransitGatewayRouteTableAnnouncementId.NotFound", (
        f"expected a NotFound for an absent announcement id, got {absent!r}"
    )

    malformed, _ = _error_code(
        lambda: ec2.delete_transit_gateway_route_table_announcement(
            TransitGatewayRouteTableAnnouncementId=_MALFORMED_ANNOUNCEMENT_ID
        )
    )
    assert malformed == "InvalidTransitGatewayRouteTableAnnouncementId.Malformed", (
        f"expected a distinct Malformed code for an unparseable id, got {malformed!r}"
    )
    assert malformed != absent, "absent and malformed ids must not collapse to one error code"

    dry_run, dry_run_message = _error_code(
        lambda: ec2.delete_transit_gateway_route_table_announcement(
            TransitGatewayRouteTableAnnouncementId=_ABSENT_ANNOUNCEMENT_ID, DryRun=True
        )
    )
    assert dry_run == "DryRunOperation", (
        f"expected DryRun to be answered before the existence check (DryRunOperation), "
        f"got {dry_run!r}"
    )
    assert dry_run_message == "Request would have succeeded, but DryRun flag is set.", (
        f"expected the exact DryRunOperation message AWS returns, got {dry_run_message!r}"
    )

    # Effect absent: the DryRun neither created nor removed anything, and the read path agrees
    # with the write path about the id being absent.
    described, _ = _error_code(
        lambda: ec2.describe_transit_gateway_route_table_announcements(
            TransitGatewayRouteTableAnnouncementIds=[_ABSENT_ANNOUNCEMENT_ID]
        )
    )
    assert described == "InvalidTransitGatewayRouteTableAnnouncementId.NotFound", (
        f"expected the describe path to agree that the id is absent, got {described!r}"
    )


# ===== helpers =====


def _error_code(fn):
    try:
        resp = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected a refusal, the call succeeded: {resp!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
