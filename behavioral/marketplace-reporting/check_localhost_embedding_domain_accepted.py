"""localhost-embedding-domain-accepted."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "localhost-embedding-domain-accepted"
GROUP = "data-plane"
SERVICES = ["marketplace-reporting"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """For an unentitled caller, GetBuyerDashboard answers the same UnauthorizedException 'Unauthorized'
    for an http://localhost:<port> embedding domain as for an https:// domain: the localhost branch of
    the pattern is valid and is not singled out by a shape error."""
    mkr = _mkr_client(ctx)
    account_id = _caller_account_id(ctx)
    arn = _agreement_arn(account_id)

    control = _error_for(mkr, arn, ["https://example.com"])
    local = _error_for(mkr, arn, ["http://localhost:3000"])

    assert control == ("UnauthorizedException", "Unauthorized"), f"baseline: got {control}"
    assert local == ("UnauthorizedException", "Unauthorized"), (
        f"the pattern's localhost alternation must be rejected the same way as a "
        f"canonical https:// domain for an unauthorized caller (auth precedes "
        f"validation); got {local}"
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
