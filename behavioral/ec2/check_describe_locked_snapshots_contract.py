"""describe-locked-snapshots-contract."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-locked-snapshots-contract"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeLockedSnapshots: success contract (list payload + DryRun) and a malformed
    SnapshotIds entry rejected by the service."""
    ec2 = ctx.client("ec2")

    resp = ec2.describe_locked_snapshots(MaxResults=5)
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200
    # Read the response body directly: exactly one field besides ResponseMetadata/NextToken
    # must carry the (possibly empty) list of locked-snapshot records.
    body_keys = [k for k in resp if k not in ("ResponseMetadata", "NextToken")]
    assert len(body_keys) == 1, f"expected exactly one body field, got {body_keys}"
    snapshots = resp[body_keys[0]]
    _assert_page_contract(snapshots, resp.get("NextToken"), max_results=5)

    _assert_dry_run_ok(lambda: ec2.describe_locked_snapshots(DryRun=True))

    # SnapshotIds carries no min/max/pattern constraint in the model (unlike MaxResults,
    # whose 5-1000 range botocore's own parameter validator enforces before the request
    # ever leaves the SDK — a rejection there would prove nothing about the service), so
    # a malformed entry here is rejected by EC2 itself.
    code, message = _client_error(lambda: ec2.describe_locked_snapshots(SnapshotIds=["not-a-real-snapshot-id"]))
    assert code == "InvalidRequest", f"expected InvalidRequest, got {code!r} ({message!r})"
    expected_message = "1 validation error detected: Value '[not-a-real-snapshot-id]' at 'snapshotIds' failed to satisfy constraint: Member must satisfy constraint: [Member must have length less than or equal to 64, Member must have length greater than or equal to 1, Member must satisfy regular expression pattern: ^snap-[0-9a-f]+$]"
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
