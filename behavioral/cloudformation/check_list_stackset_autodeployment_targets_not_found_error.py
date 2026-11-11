"""list-stackset-autodeployment-targets-not-found-error."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "list-stackset-autodeployment-targets-not-found-error"
GROUP = "error-semantics"
SERVICES = ["cloudformation"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListStackSetAutoDeploymentTargets fails with ValidationError "Auto-deployment targets are only
    available for service-managed stack sets" for an existing self-managed stack set and with
    StackSetNotFoundException "StackSet <name> not found" for a name never created."""
    cfn = ctx.client("cloudformation")
    real_name = ctx.unique_name("sim2real-behav-ssadt-")
    cfn.create_stack_set(
        StackSetName=real_name,
        TemplateBody=_wait_handle_template(),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: cfn.delete_stack_set(StackSetName=real_name))

    # Positive control: the StackSet genuinely exists, so this failure must be about
    # its self-managed permission model, not a lookup miss -- proving the account,
    # credentials and this exact operation are otherwise healthy.
    real_code, real_message = _error(
        lambda: cfn.list_stack_set_auto_deployment_targets(StackSetName=real_name)
    )
    assert real_code == "ValidationError", (
        f"expected ValidationError for a self-managed StackSet, got {real_code}"
    )
    assert real_message == "Auto-deployment targets are only available for service-managed stack sets", (
        f"unexpected ValidationError message {real_message!r}"
    )

    bogus_name = real_name + "-absent"
    bogus_code, bogus_message = _error(
        lambda: cfn.list_stack_set_auto_deployment_targets(StackSetName=bogus_name)
    )
    assert bogus_code == "StackSetNotFoundException", f"expected StackSetNotFoundException, got {bogus_code}"
    assert bogus_message == f"StackSet {bogus_name} not found", (
        f"unexpected StackSetNotFoundException message {bogus_message!r}"
    )


def _wait_handle_template() -> str:
    return json.dumps({"Resources": {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}}})


def _error(fn):
    """Call fn(); return botocore (Error.Code, Error.Message). An unexpected success raises, so a target
    that accepts input AWS refuses fails as an acceptance rather than as an error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
