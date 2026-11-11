"""concurrent-calls-yield-unique-embed-urls."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-calls-yield-unique-embed-urls"
GROUP = "concurrency"
SERVICES = ["marketplace-reporting"]


@tags("axis:rejection", "cap:unclassified", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Five concurrent GetBuyerDashboard calls from an unentitled caller each fail independently with
    UnauthorizedException 'Unauthorized' and HTTP 401: no call slips through and none gets a different
    error under concurrent load."""
    mkr = _mkr_client(ctx)
    account_id = _caller_account_id(ctx)
    arn = _agreement_arn(account_id)
    domains = ["https://example.com"]

    n = 5

    def _call():
        try:
            return ("SUCCESS", mkr.get_buyer_dashboard(dashboardIdentifier=arn, embeddingDomains=domains))
        except ClientError as err:
            error = err.response["Error"]
            return (
                (error["Code"], error.get("Message")),
                err.response["ResponseMetadata"]["HTTPStatusCode"],
            )

    with ThreadPoolExecutor(max_workers=n) as pool:
        results = [f.result() for f in [pool.submit(_call) for _ in range(n)]]

    assert len(results) == n, f"expected {n} completed futures, got {len(results)}: {results}"
    for outcome, status in results:
        assert outcome != "SUCCESS", f"a concurrent call succeeded: {status!r} across results={results}"
        code, message = outcome
        assert code == "UnauthorizedException", (
            f"expected every concurrent call to independently fail with "
            f"UnauthorizedException, got {code!r} across results={results}"
        )
        assert message == "Unauthorized", f"expected the message 'Unauthorized', got {message!r}"
        # Every call gets its OWN 401, not a mix of e.g. one 401 + N-1 throttled/500s.
        assert status == 401, results


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
