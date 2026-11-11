"""op-contract-describeApplicationStatus."""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describeApplicationStatus"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeApplicationStatus returns a well-formed listing and enforces the DryRun contract."""
    ec2 = ctx.client("ec2")
    _require_op(ec2, "describe_application_status")

    # success path: account-wide application status listing (no InstanceIds filter)
    response = ec2.describe_application_status()
    assert response["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"expected 200 from DescribeApplicationStatus, got {response['ResponseMetadata']['HTTPStatusCode']!r}"
    )
    # substantive assertion directly on the response body (confirmed shape: a top-level
    # "ApplicationStatuses" structure wrapping an "Instances" list -- see the CLI Output
    # section for DescribeApplicationStatus).
    assert "ApplicationStatuses" in response, f"expected ApplicationStatuses in response body: {response!r}"
    statuses = response["ApplicationStatuses"]
    assert isinstance(statuses, dict), f"expected ApplicationStatuses to be a structure, got {statuses!r}"
    assert "Instances" in statuses, f"expected Instances in ApplicationStatuses body: {statuses!r}"
    instances = statuses["Instances"]
    assert isinstance(instances, list), f"expected Instances to be a list, got {instances!r}"
    for item in instances:
        assert isinstance(item, dict), f"instance record should be dict-shaped, got {item!r}"
        # each per-instance record should identify the instance and/or its rolled-up status
        assert "InstanceId" in item or "ApplicationStatus" in item, (
            f"instance record missing InstanceId/ApplicationStatus: {item!r}"
        )
    if not instances:
        # pagination contract: nextToken must be null/absent when there is nothing more to return
        assert response.get("NextToken") in (None, ""), (
            "NextToken should be empty/absent when the result set is empty"
        )

    # error boundary: DryRun=True must short-circuit with DryRunOperation when the caller has permission
    code, message = _error(lambda: ec2.describe_application_status(DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code!r}"
    assert message == _DRY_RUN_MESSAGE, f"expected DryRun message {_DRY_RUN_MESSAGE!r}, got {message!r}"


def _require_op(client: Any, op_name: str) -> None:

    if not hasattr(client, op_name):
        raise AssertionError(f"ec2 client missing operation {op_name!r} (botocore too old)")


def _error(fn):
    """Call fn(); return its error as (code, message). An unexpected SUCCESS raises rather than
    returning a falsy sentinel."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
