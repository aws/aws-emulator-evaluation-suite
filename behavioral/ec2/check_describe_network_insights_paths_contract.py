"""describe-network-insights-paths-contract."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-network-insights-paths-contract"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeNetworkInsightsPaths: success contract (list payload + DryRun) and MaxResults
    above the documented maximum (100) rejection."""
    ec2 = ctx.client("ec2")

    resp = ec2.describe_network_insights_paths(MaxResults=1)
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200
    paths = resp["NetworkInsightsPaths"]
    _assert_page_contract(paths, resp.get("NextToken"), max_results=1)

    _assert_dry_run_ok(lambda: ec2.describe_network_insights_paths(DryRun=True))

    # The service reports this specific out-of-range condition as InvalidMaxResults
    # (not the generic InvalidParameterValue).
    code, message = _error(lambda: ec2.describe_network_insights_paths(MaxResults=1000))
    assert code == "InvalidMaxResults", f"expected InvalidMaxResults, got {code!r}"
    expected = "MaxResults must be between 1 and 100"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


def _assert_page_contract(items, next_token, *, max_results):
    # Substantive body/state assertion: the returned page must never exceed the
    # requested MaxResults, and per the documented contract NextToken is null once
    # fewer than MaxResults items come back (there is nothing left to paginate).
    assert isinstance(items, list)
    assert len(items) <= max_results, f"expected at most {max_results} items, got {len(items)}"
    if len(items) < max_results:
        assert not next_token, "NextToken must be empty when the returned page is not full"


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, call unexpectedly succeeded: {result!r}")


def _assert_dry_run_ok(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message", "")
        assert code == "DryRunOperation", f"expected DryRunOperation, got {code!r}"
        assert message == _DRY_RUN_MESSAGE, f"unexpected DryRunOperation message {message!r}"
        return
    raise AssertionError("expected DryRunOperation error, call unexpectedly succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
