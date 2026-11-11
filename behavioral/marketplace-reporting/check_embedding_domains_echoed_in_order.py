"""embedding-domains-echoed-in-order."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "embedding-domains-echoed-in-order"
GROUP = "data-plane"
SERVICES = ["marketplace-reporting"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetBuyerDashboard with one embedding domain and with the maximum of two both fail with the same
    UnauthorizedException 'Unauthorized' for an unentitled caller: the domain count within [1, 2] does
    not change the authorization answer."""
    mkr = _mkr_client(ctx)
    account_id = _caller_account_id(ctx)
    arn = _agreement_arn(account_id)

    def _error_for(domains):
        """The (code, message) GetBuyerDashboard fails with; a success raises."""
        try:
            resp = mkr.get_buyer_dashboard(dashboardIdentifier=arn, embeddingDomains=domains)
        except ClientError as err:
            return err.response["Error"]["Code"], err.response["Error"].get("Message")
        raise AssertionError(f"expected GetBuyerDashboard to fail, it succeeded: {resp}")

    one_domain = _error_for(["https://foo.example.com"])
    two_domain = _error_for(["https://foo.example.com", "https://bar.example.com"])

    assert one_domain == ("UnauthorizedException", "Unauthorized"), one_domain
    assert two_domain == ("UnauthorizedException", "Unauthorized"), two_domain


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
