"""invalid-operation-error-org-and-stackset-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "invalid-operation-error-org-and-stackset-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudformation"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateStackInstances with both Accounts and DeploymentTargets is ValidationError and changes no
    instances, while Accounts alone is accepted; DescribeOrganizationsAccess as DELEGATED_ADMIN from a
    non-delegated account is InvalidOperationException."""
    cfn = ctx.client("cloudformation")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]
    stackset_name = ctx.unique_name("sim2real-ssinvop-")
    template = json.dumps({"Resources": {"Topic": {"Type": "AWS::SNS::Topic"}}})

    cfn.create_stack_set(
        StackSetName=stackset_name,
        TemplateBody=template,
        Tags=[{"Key": "sim2real-behav", "Value": "invalid-operation-error-org-and-stackset-rejected"}],
    )
    ctx.on_cleanup(lambda: _swallow(lambda: cfn.delete_stack_set(StackSetName=stackset_name)))

    # Positive control: Accounts-only targeting must be accepted (an OperationId); the operation
    # itself may later fail on role assumption, which does not matter here.
    valid_op_id = cfn.create_stack_instances(
        StackSetName=stackset_name, Accounts=[account], Regions=[ctx.region]
    )["OperationId"]
    _await_operation(cfn, stackset_name, valid_op_id)
    # Without the StackSet admin role the instance is left OUTDATED/FAILED; DeleteStackInstances is
    # async, so await it or the leftover record is still visible to the effect-absent read below.
    delete_op_id = _op_id_or_none(
        lambda: cfn.delete_stack_instances(
            StackSetName=stackset_name, Accounts=[account], Regions=[ctx.region], RetainStacks=True
        )
    )
    if delete_op_id is not None:
        _await_operation(cfn, stackset_name, delete_op_id)
    ctx.on_cleanup(
        lambda: _swallow(
            lambda: cfn.delete_stack_instances(
                StackSetName=stackset_name, Accounts=[account], Regions=[ctx.region], RetainStacks=False
            )
        )
    )
    baseline_instances = cfn.list_stack_instances(StackSetName=stackset_name)["Summaries"]

    error = _client_error(
        lambda: cfn.create_stack_instances(
            StackSetName=stackset_name,
            Accounts=[account],
            DeploymentTargets={"OrganizationalUnitIds": ["ou-fake-00000000"]},
            Regions=[ctx.region],
        )
    )
    assert error.get("Code") == "ValidationError", (
        f"CreateStackInstances with both Accounts and DeploymentTargets set: expected "
        f"ValidationError, got {error!r}"
    )
    assert error.get("Message") == "Cannot specify both Accounts and DeploymentTargets", (
        f"expected message 'Cannot specify both Accounts and DeploymentTargets', got {error!r}"
    )

    instances = cfn.list_stack_instances(StackSetName=stackset_name)["Summaries"]
    assert instances == baseline_instances, (
        f"the rejected CreateStackInstances call changed stack instances: "
        f"before={baseline_instances!r} after={instances!r}"
    )

    error2 = _client_error(lambda: cfn.describe_organizations_access(CallAs="DELEGATED_ADMIN"))
    assert error2.get("Code") == "InvalidOperationException", (
        f"DescribeOrganizationsAccess(CallAs=DELEGATED_ADMIN) from a non-delegated-admin "
        f"account: expected InvalidOperationException, got {error2!r}"
    )
    assert error2.get("Message") == "Account used is not a delegated administrator", (
        f"expected message 'Account used is not a delegated administrator', got {error2!r}"
    )

    # An unrelated read still succeeds, so the rejection is due to the delegated-admin precondition.
    cfn.list_stack_sets(Status="ACTIVE")


def _client_error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _swallow(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "OperationNotFoundException",
            "StackSetNotFoundException",
        ):
            raise


def _op_id_or_none(fn):
    """fn()'s OperationId, or None if it raised a ClientError (nothing to await)."""
    try:
        return fn()["OperationId"]
    except ClientError:
        return None


def _await_operation(cfn, stackset_name: str, operation_id: str, timeout_s: float = 180.0) -> None:
    """Wait for a StackSet operation to reach a terminal state; the outcome is not asserted because
    without StackSets admin/execution roles it fails on role assumption."""
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cfn.describe_stack_set_operation(
            StackSetName=stackset_name, OperationId=operation_id
        )["StackSetOperation"]["Status"]
        if status in ("SUCCEEDED", "FAILED", "STOPPED"):
            return
        time.sleep(5)
    raise AssertionError(
        f"positive-control stack set operation {operation_id} did not reach a terminal "
        f"state within {timeout_s}s; last status={status!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
