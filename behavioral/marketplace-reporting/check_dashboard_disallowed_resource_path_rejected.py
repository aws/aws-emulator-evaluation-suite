"""dashboard-disallowed-resource-path-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "dashboard-disallowed-resource-path-rejected"
GROUP = "overly-permissive"
SERVICES = ["marketplace-reporting"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """For an unentitled caller, GetBuyerDashboard answers UnauthorizedException 'Unauthorized' both for an
    allow-listed dashboard ARN and for a well-formed ARN naming an unlisted dashboard path:
    authorization runs before the allow-list check."""
    mkr = _mkr_client(ctx)
    account_id = _caller_account_id(ctx)
    valid_arn = _agreement_arn(account_id)
    domains = ["https://example.com"]

    bad_arn = (
        f"arn:aws:aws-marketplace::{account_id}:AWSMarketplace/ReportingData/"
        "SomeOther_V1/Dashboard/NotARealDashboard_V1"
    )

    control = _error_for(mkr, valid_arn, domains)
    bad = _error_for(mkr, bad_arn, domains)

    assert control == ("UnauthorizedException", "Unauthorized"), f"baseline: got {control}"
    assert bad == ("UnauthorizedException", "Unauthorized"), (
        f"an unlisted dashboard resource path must be rejected the same way as an "
        f"allow-listed one for an unauthorized caller (auth precedes validation); "
        f"got {bad}"
    )


def _error_for(mkr, arn, domains):
    """The (code, message) GetBuyerDashboard fails with; a success raises."""
    try:
        resp = mkr.get_buyer_dashboard(dashboardIdentifier=arn, embeddingDomains=domains)
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected GetBuyerDashboard to fail, it succeeded: {resp}")


def _mkr_client(ctx):
    """marketplace-reporting is served only in us-east-1, so the client is pinned there through
    ctx.client(..., region=); every target takes the same code path and Context keeps the
    credential, endpoint and retry wiring."""
    return ctx.client("marketplace-reporting", region="us-east-1")


def _caller_account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _agreement_arn(account_id: str) -> str:
    return (
        f"arn:aws:aws-marketplace::{account_id}:AWSMarketplace/ReportingData/"
        "Agreement_V1/Dashboard/AgreementSummary_V1"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
