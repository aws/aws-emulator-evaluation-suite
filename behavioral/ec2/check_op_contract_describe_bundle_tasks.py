"""op-contract-describeBundleTasks."""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describeBundleTasks"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeBundleTasks lists bundle tasks and rejects a nonexistent BundleId with NotFound."""
    ec2 = ctx.client("ec2")
    _require_op(ec2, "describe_bundle_tasks")

    # success path: account-wide bundle task listing (most accounts have none, which is fine -
    # the contract under test is that the call succeeds and returns the documented list shape)
    response = ec2.describe_bundle_tasks()
    status = response["ResponseMetadata"]["HTTPStatusCode"]
    assert status == 200, f"expected HTTP 200 from DescribeBundleTasks, got {status!r}"
    assert "BundleTasks" in response, f"expected a BundleTasks key, got keys {sorted(response)!r}"
    bundle_tasks = response["BundleTasks"]
    assert isinstance(bundle_tasks, list), f"expected BundleTasks to be a list, got {type(bundle_tasks).__name__}"

    # error boundary: a syntactically valid but nonexistent BundleId is rejected with the
    # long-standing EC2 bundle-task NotFound code (distinct from a permission-check dry run)
    code, message = _error(
        lambda: ec2.describe_bundle_tasks(BundleIds=["bun-00000000"])
    )
    assert code == "InvalidBundleID.NotFound", f"expected InvalidBundleID.NotFound, got {code!r}"
    assert message == "Invalid bundle ids: bun-00000000", f"unexpected InvalidBundleID.NotFound message {message!r}"


def _require_op(client: Any, op_name: str) -> None:

    if not hasattr(client, op_name):
        raise AssertionError(f"ec2 client missing operation {op_name!r} (botocore too old)")


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. A call that succeeds
    raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
