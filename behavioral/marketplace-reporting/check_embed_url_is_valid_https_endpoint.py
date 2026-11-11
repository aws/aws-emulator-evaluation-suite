"""embed-url-is-valid-https-endpoint."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "embed-url-is-valid-https-endpoint"
GROUP = "data-plane"
SERVICES = ["marketplace-reporting"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetBuyerDashboard from an unentitled caller fails UnauthorizedException with HTTP 401 and message
    'Unauthorized', and no embedUrl appears anywhere in the error response: an auth failure never leaks
    an embedding URL."""
    mkr = _mkr_client(ctx)
    account_id = _caller_account_id(ctx)
    arn = _agreement_arn(account_id)

    try:
        resp = mkr.get_buyer_dashboard(
            dashboardIdentifier=arn, embeddingDomains=["https://example.com"]
        )
        raise AssertionError(f"expected UnauthorizedException, call succeeded: {resp}")
    except ClientError as err:
        error = err.response["Error"]
        assert error["Code"] == "UnauthorizedException", f"expected UnauthorizedException, got {error['Code']}"
        status = err.response["ResponseMetadata"]["HTTPStatusCode"]
        assert status == 401, f"expected HTTP 401 for UnauthorizedException, got {status}"
        message = error.get("Message")
        assert message == "Unauthorized", f"expected message 'Unauthorized', got {message!r}"
        assert "embedUrl" not in repr(err.response), (
            f"UnauthorizedException response must not leak embedUrl, got {err.response!r}"
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
