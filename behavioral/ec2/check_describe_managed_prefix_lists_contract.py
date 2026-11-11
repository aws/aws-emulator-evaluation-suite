"""describe-managed-prefix-lists-contract."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-managed-prefix-lists-contract"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:rejection", "cap:c1", "cap:c5", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeManagedPrefixLists: AWS-managed lists are visible by default, DryRun works, and
    MaxResults above the documented maximum (100) is rejected."""
    ec2 = ctx.client("ec2")

    resp = ec2.describe_managed_prefix_lists(MaxResults=1)
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200
    prefix_lists = resp["PrefixLists"]
    _assert_page_contract(prefix_lists, resp.get("NextToken"), max_results=1)
    # Every account/region has AWS-managed prefix lists (e.g. com.amazonaws.<region>.s3)
    # visible without any filter.
    all_prefix_lists = ec2.describe_managed_prefix_lists(MaxResults=100)["PrefixLists"]
    assert any(
        pl.get("OwnerId") == "AWS" or pl.get("PrefixListName", "").startswith("com.amazonaws.")
        for pl in all_prefix_lists
    ), "expected at least one AWS-managed prefix list in the default listing"

    _assert_dry_run_ok(lambda: ec2.describe_managed_prefix_lists(DryRun=True))

    # MaxResults valid range is documented as 1-100; above the maximum must be rejected.
    # The service reports this specific out-of-range condition as InvalidMaxResults
    # (not the generic InvalidParameterValue).
    code, message = _client_error(lambda: ec2.describe_managed_prefix_lists(MaxResults=1000))
    assert code == "InvalidMaxResults", f"expected InvalidMaxResults, got {code!r}"
    expected_message = "The requested max results (1000) is larger than limit (100)."
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"


def _assert_page_contract(items, next_token, *, max_results):
    # Substantive body/state assertion: the returned page must never exceed the
    # requested MaxResults, and per the documented contract NextToken is null once
    # fewer than MaxResults items come back (there is nothing left to paginate).
    assert isinstance(items, list)
    assert len(items) <= max_results, f"expected at most {max_results} items, got {len(items)}"
    if len(items) < max_results:
        assert not next_token, "NextToken must be empty when the returned page is not full"


def _client_error(fn):
    """Call fn() and return the (code, message) it is refused with; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _assert_dry_run_ok(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message")
        assert code == "DryRunOperation", f"expected DryRunOperation, got {code!r}"
        assert message == _DRY_RUN_MESSAGE, f"expected {_DRY_RUN_MESSAGE!r}, got {message!r}"
        return
    raise AssertionError("expected DryRunOperation error, call unexpectedly succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
