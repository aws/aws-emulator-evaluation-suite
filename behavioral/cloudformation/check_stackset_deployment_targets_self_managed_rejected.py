"""stackset-deployment-targets-self-managed-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "stackset-deployment-targets-self-managed-rejected"
GROUP = "state-machine"
SERVICES = ["cloudformation"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateStackInstances rejects OU-based DeploymentTargets on a SELF_MANAGED StackSet (valid
    only for SERVICE_MANAGED); the same call addressed by Accounts is the positive control."""
    cfn = ctx.client("cloudformation")
    account = ctx.client("sts").get_caller_identity()["Account"]

    stackset_name = ctx.unique_name("sim2real-ss-selfmanaged-")
    template = json.dumps(
        {"Resources": {"Param": {"Type": "AWS::SSM::Parameter", "Properties": {"Type": "String", "Value": "1"}}}}
    )
    cfn.create_stack_set(
        StackSetName=stackset_name,
        TemplateBody=template,
        PermissionModel="SELF_MANAGED",
    )
    ctx.on_cleanup(lambda: _safe(lambda: cfn.delete_stack_set(StackSetName=stackset_name)))

    error = _error(
        lambda: cfn.create_stack_instances(
            StackSetName=stackset_name,
            DeploymentTargets={"OrganizationalUnitIds": ["ou-fake1234-abcdefgh"]},
            Regions=[ctx.region],
        )
    )
    expected = (
        "ValidationError",
        "StackSets with SELF_MANAGED permission model can only have accounts as target",
    )
    assert error == expected, (
        f"expected {expected!r} using DeploymentTargets against a SELF_MANAGED StackSet, "
        f"got {error!r}"
    )

    # No stack instances should have been created as a side effect of the rejected call.
    instances = cfn.list_stack_instances(StackSetName=stackset_name)["Summaries"]
    assert instances == [], f"expected zero stack instances after a rejected call, got {instances!r}"

    # Positive control: Accounts addressing is valid for SELF_MANAGED, so this call must clear
    # parameter validation.
    operation_id, positive_code = _create_or_code(
        lambda: cfn.create_stack_instances(
            StackSetName=stackset_name, Accounts=[account], Regions=[ctx.region]
        )
    )
    assert positive_code != "ValidationError", (
        f"CreateStackInstances(Accounts=...) against the same SELF_MANAGED StackSet must clear "
        f"parameter validation (it may still fail later, e.g. on role assumption); got "
        f"ValidationError, which would make the DeploymentTargets rejection above indistinguishable "
        f"from a blanket refusal"
    )
    if operation_id is not None:
        ctx.on_cleanup(
            lambda: _safe(
                lambda: cfn.delete_stack_instances(
                    StackSetName=stackset_name,
                    Accounts=[account],
                    Regions=[ctx.region],
                    RetainStacks=False,
                )
            )
        )
        _await_terminal(cfn, stackset_name, operation_id)


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "OperationNotFoundException",
            "StackSetNotFoundException",
        ):
            raise


def _error(fn):
    """(Error.Code, Error.Message) of the rejection fn() raises; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _create_or_code(fn):
    """Run a CreateStackInstances-shaped call; return (OperationId, None) on synchronous
    acceptance or (None, error_code) on synchronous rejection."""
    from botocore.exceptions import ClientError

    try:
        return fn()["OperationId"], None
    except ClientError as exc:
        return None, exc.response["Error"]["Code"]


def _await_terminal(cfn, stackset_name: str, operation_id: str, timeout_s: float = 120.0) -> None:
    import time

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = cfn.describe_stack_set_operation(
            StackSetName=stackset_name, OperationId=operation_id
        )["StackSetOperation"]["Status"]
        if status in ("SUCCEEDED", "FAILED", "STOPPED"):
            return
        time.sleep(5.0)
    raise AssertionError(f"stack set operation {operation_id} did not reach a terminal state within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
