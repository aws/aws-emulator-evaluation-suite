"""agreement-dashboard-embed-success."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "agreement-dashboard-embed-success"
GROUP = "data-plane"
SERVICES = ["marketplace-reporting"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetBuyerDashboard for the AgreementSummary_V1 dashboard from a caller without the
    procurement-insights entitlement fails closed with UnauthorizedException 'Unauthorized' (HTTP 401),
    and the error response carries no embedUrl or echoed dashboardIdentifier."""
    from botocore.exceptions import ClientError

    mkr = _mkr_client(ctx)
    account_id = _caller_account_id(ctx)
    arn = _agreement_arn(account_id)
    domain = "https://example.com"

    try:
        resp = mkr.get_buyer_dashboard(dashboardIdentifier=arn, embeddingDomains=[domain])
        raise AssertionError(
            f"expected an unentitled caller to be rejected with UnauthorizedException, "
            f"call unexpectedly succeeded: {resp}"
        )
    except ClientError as err:
        code = err.response["Error"]["Code"]
        assert code == "UnauthorizedException", (
            f"expected UnauthorizedException for a valid-shape request from an "
            f"unentitled caller, got {code}"
        )
        message = err.response["Error"].get("Message")
        assert message == "Unauthorized", f"expected message 'Unauthorized', got {message!r}"
        status = err.response["ResponseMetadata"]["HTTPStatusCode"]
        assert status == 401, f"expected HTTP 401 for UnauthorizedException, got {status}"
        assert "embedUrl" not in err.response, (
            f"UnauthorizedException error response must not leak embedUrl: {err.response}"
        )
        assert "dashboardIdentifier" not in err.response, (
            f"UnauthorizedException error response must not echo the request's "
            f"dashboardIdentifier: {err.response}"
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
