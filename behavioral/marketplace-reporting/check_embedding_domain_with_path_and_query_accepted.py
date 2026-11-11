"""embedding-domain-with-path-and-query-accepted."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "embedding-domain-with-path-and-query-accepted"
GROUP = "data-plane"
SERVICES = ["marketplace-reporting"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An embedding domain with a trailing path and query string, valid under the embeddingDomains
    pattern, reaches the service and fails only UnauthorizedException 'Unauthorized' (HTTP 401) for an
    unentitled caller, with no embedUrl in the error response."""
    mkr = _mkr_client(ctx)
    account_id = _caller_account_id(ctx)
    arn = _agreement_arn(account_id)
    domain = "https://example.com/app?tab=1"

    try:
        resp = mkr.get_buyer_dashboard(dashboardIdentifier=arn, embeddingDomains=[domain])
        raise AssertionError(f"expected UnauthorizedException, call succeeded: {resp}")
    except ClientError as err:
        code = err.response["Error"]["Code"]
        assert code == "UnauthorizedException", (
            f"expected UnauthorizedException for a valid-shape path+query domain from "
            f"an unentitled caller, got {code}"
        )
        message = err.response["Error"].get("Message")
        assert message == "Unauthorized", f"expected message 'Unauthorized', got {message!r}"
        assert err.response["ResponseMetadata"]["HTTPStatusCode"] == 401, (
            f"expected HTTP 401, got {err.response['ResponseMetadata']['HTTPStatusCode']}"
        )
        assert "embedUrl" not in err.response, f"embedUrl leaked in error response: {err.response}"


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
