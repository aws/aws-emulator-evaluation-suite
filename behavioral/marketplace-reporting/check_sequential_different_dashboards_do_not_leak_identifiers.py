"""sequential-different-dashboards-do-not-leak-identifiers."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sequential-different-dashboards-do-not-leak-identifiers"
GROUP = "data-plane"
SERVICES = ["marketplace-reporting"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Back-to-back GetBuyerDashboard calls for the Agreement and then the BillingEvent dashboard from an
    unentitled caller both fail UnauthorizedException 'Unauthorized': the second call is authorized on its
    own, not let through by the first."""
    mkr = _mkr_client(ctx)
    account_id = _caller_account_id(ctx)
    agreement_arn = _agreement_arn(account_id)
    billing_arn = _billing_arn(account_id)
    domains = ["https://example.com"]

    def _error_for(arn):
        """The (code, message) GetBuyerDashboard fails with; a success raises."""
        try:
            resp = mkr.get_buyer_dashboard(dashboardIdentifier=arn, embeddingDomains=domains)
        except ClientError as err:
            return err.response["Error"]["Code"], err.response["Error"].get("Message")
        raise AssertionError(f"expected GetBuyerDashboard({arn}) to fail, it succeeded: {resp}")

    code1 = _error_for(agreement_arn)
    code2 = _error_for(billing_arn)

    assert code1 == ("UnauthorizedException", "Unauthorized"), (
        f"Agreement dashboard call: expected UnauthorizedException, got {code1}"
    )
    assert code2 == ("UnauthorizedException", "Unauthorized"), (
        f"BillingEvent dashboard call: expected UnauthorizedException, got {code2} "
        f"(a bare single-slot auth cache would let this second, different-ARN call "
        f"through as SUCCESS after the first call was already checked)"
    )


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


def _billing_arn(account_id: str) -> str:
    return (
        f"arn:aws:aws-marketplace::{account_id}:AWSMarketplace/ReportingData/"
        "BillingEvent_V1/Dashboard/CostAnalysis_V1"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
