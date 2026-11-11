"""embed-url-distinct-across-repeated-calls."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "embed-url-distinct-across-repeated-calls"
GROUP = "data-plane"
SERVICES = ["marketplace-reporting"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two sequential, identical GetBuyerDashboard calls from an unentitled caller both fail with
    UnauthorizedException 'Unauthorized' and HTTP 401: the authorization decision does not vary from
    call to call."""
    mkr = _mkr_client(ctx)
    account_id = _caller_account_id(ctx)
    arn = _agreement_arn(account_id)
    domains = ["https://example.com"]

    def _call():
        try:
            resp = mkr.get_buyer_dashboard(dashboardIdentifier=arn, embeddingDomains=domains)
        except ClientError as err:
            error = err.response["Error"]
            return (
                (error["Code"], error.get("Message")),
                err.response["ResponseMetadata"]["HTTPStatusCode"],
            )
        raise AssertionError(f"expected UnauthorizedException, call succeeded: {resp}")

    code1, status1 = _call()
    code2, status2 = _call()

    assert code1 == ("UnauthorizedException", "Unauthorized"), (
        f"first call: expected UnauthorizedException 'Unauthorized', got {code1}"
    )
    assert code2 == ("UnauthorizedException", "Unauthorized"), (
        f"second call: expected UnauthorizedException 'Unauthorized', got {code2}"
    )
    assert status1 == 401, f"first call: expected HTTP 401, got {status1}"
    assert status2 == 401, f"second call: expected HTTP 401, got {status2}"
    assert code1 == code2 and status1 == status2, (
        f"repeated identical calls diverged: code {code1!r} vs {code2!r}, "
        f"status {status1!r} vs {status2!r}"
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
