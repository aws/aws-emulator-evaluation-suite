"""describe-network-insights-access-scope-analyses-contract."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-network-insights-access-scope-analyses-contract"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeNetworkInsightsAccessScopeAnalyses: success contract (paginated list payload +
    DryRun) and rejection of a filter, since the operation documents 'there are no supported
    filters'."""
    ec2 = ctx.client("ec2")

    resp = ec2.describe_network_insights_access_scope_analyses(MaxResults=1)
    status = resp["ResponseMetadata"]["HTTPStatusCode"]
    assert status == 200, f"expected HTTP 200, got {status!r}"
    analyses = resp["NetworkInsightsAccessScopeAnalyses"]
    _assert_page_contract(analyses, resp.get("NextToken"), max_results=1)

    _assert_dry_run_ok(lambda: ec2.describe_network_insights_access_scope_analyses(DryRun=True))

    # The service reports an unrecognized filter name as InvalidFilter (not
    # InvalidParameterValue).
    code, message = _error(
        lambda: ec2.describe_network_insights_access_scope_analyses(
            Filters=[{"Name": "sim2real-bogus-filter", "Values": ["x"]}]
        )
    )
    assert code == "InvalidFilter", f"expected InvalidFilter, got {code!r}"
    expected = "Filter name must be one of [status, findings-found]"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


def _assert_page_contract(items, next_token, *, max_results):
    # Substantive body/state assertion: the returned page must never exceed the
    # requested MaxResults, and per the documented contract NextToken is null once
    # fewer than MaxResults items come back (there is nothing left to paginate).
    assert isinstance(items, list), f"expected a list of analyses, got {type(items).__name__}"
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
