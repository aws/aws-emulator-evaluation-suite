"""op-contract-describeCapacityManagerDataExports."""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describeCapacityManagerDataExports"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeCapacityManagerDataExports lists export configurations and enforces DryRun."""
    ec2 = ctx.client("ec2")
    _require_op(ec2, "describe_capacity_manager_data_exports")

    # success path: account-wide listing (no CapacityManagerDataExportIds filter); a fresh
    # account has no export configurations, which is a valid, well-formed empty result.
    response = ec2.describe_capacity_manager_data_exports()
    assert response["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"expected 200 for describe_capacity_manager_data_exports, "
        f"got {response['ResponseMetadata']['HTTPStatusCode']!r}"
    )
    # substantive assertion directly on the response body (confirmed shape: top-level
    # "CapacityManagerDataExports" list -- see the CLI Output section / --query hint for
    # describe-capacity-manager-data-exports).
    assert "CapacityManagerDataExports" in response, (
        f"expected CapacityManagerDataExports in response body: {response!r}"
    )
    exports = response["CapacityManagerDataExports"]
    assert isinstance(exports, list), f"expected CapacityManagerDataExports to be a list, got {exports!r}"
    for item in exports:
        assert isinstance(item, dict), f"data-export record should be dict-shaped, got {item!r}"
        # an export record should identify itself and its destination S3 bucket
        assert "CapacityManagerDataExportId" in item or "S3BucketName" in item, (
            f"export record missing CapacityManagerDataExportId/S3BucketName: {item!r}"
        )
    if not exports:
        # pagination contract: nextToken must be null/absent when there is nothing more to return
        assert response.get("NextToken") in (None, ""), (
            "NextToken should be empty/absent when the result set is empty"
        )

    # error boundary: DryRun=True must short-circuit with DryRunOperation when the caller has permission
    code, message = _error(lambda: ec2.describe_capacity_manager_data_exports(DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code!r}"
    assert message == _DRY_RUN_MESSAGE, f"unexpected DryRunOperation message {message!r}"


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
