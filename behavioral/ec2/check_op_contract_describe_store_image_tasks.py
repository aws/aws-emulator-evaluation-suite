"""op-contract-describe-store-image-tasks."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-describe-store-image-tasks"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeStoreImageTasks: listing without ImageIds succeeds with the documented
    shape; DryRun is the distinct error boundary."""
    ec2 = ctx.client("ec2")

    resp = ec2.describe_store_image_tasks(MaxResults=10)
    assert "StoreImageTaskResults" in resp, f"expected StoreImageTaskResults key, got keys {list(resp)}"
    results = resp["StoreImageTaskResults"]
    assert isinstance(results, list), f"expected StoreImageTaskResults to be a list, got {type(results)!r}"
    for r in results:
        for field in ("AmiId", "Bucket", "S3objectKey", "StoreTaskState"):
            assert field in r, f"missing expected field {field!r} on StoreImageTaskResult {r!r}"

    # Error boundary: DryRun.
    code, code_message = _error_code(lambda: ec2.describe_store_image_tasks(DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code!r}"
    expected_code_message = "Request would have succeeded, but DryRun flag is set."
    assert code_message == expected_code_message, f"expected message {expected_code_message!r}, got {code_message!r}"


def _error_code(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
