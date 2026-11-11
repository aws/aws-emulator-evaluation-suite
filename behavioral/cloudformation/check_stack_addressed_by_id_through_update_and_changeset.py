"""stack-addressed-by-id-through-update-and-changeset."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stack-addressed-by-id-through-update-and-changeset"
GROUP = "stack_lifecycle"
SERVICES = ["cloudformation"]

_TEMPLATE = """
AWSTemplateFormatVersion: "2010-09-09"
Parameters:
  ParamValue:
    Type: String
Resources:
  Param:
    Type: AWS::SSM::Parameter
    Properties:
      Type: String
      Value: !Ref ParamValue
Outputs:
  ParamName:
    Value: !Ref Param
"""

_TERMINAL = {
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "UPDATE_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED",
}


@tags("axis:happy-path", "cap:c3", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The StackId from CreateStack works as StackName for UpdateStack and for CreateChangeSet +
    ExecuteChangeSet, both mutating the same stack, and DescribeChangeSet resolves the human name.
    """
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-behav-cfn-byid-")
    ssm = ctx.client("ssm")

    created = cfn.create_stack(
        StackName=stack_name, TemplateBody=_TEMPLATE,
        Parameters=[{"ParameterKey": "ParamValue", "ParameterValue": "first"}],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    stack_id = created["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_id))
    status = _wait_terminal(cfn, stack_id)
    assert status == "CREATE_COMPLETE", f"create ended {status!r}, expected CREATE_COMPLETE"
    param_name = _output(cfn, stack_id, "ParamName")
    assert ssm.get_parameter(Name=param_name)["Parameter"]["Value"] == "first", (
        "the initial parameter value is not 'first'"
    )

    updated = cfn.update_stack(
        StackName=stack_id, TemplateBody=_TEMPLATE,
        Parameters=[{"ParameterKey": "ParamValue", "ParameterValue": "second"}],
    )
    assert updated["StackId"] == stack_id, (
        f"UpdateStack(StackName=<id>) returned StackId {updated['StackId']!r}, expected {stack_id!r}"
    )
    status = _wait_terminal(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"update by id ended {status!r}, expected UPDATE_COMPLETE"
    assert ssm.get_parameter(Name=param_name)["Parameter"]["Value"] == "second", (
        "UpdateStack(StackName=<id>) did not change the parameter value"
    )
    by_name = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    assert by_name["StackId"] == stack_id, "the stack addressed by name diverged from the id"

    cs_name = ctx.unique_name("sim2real-behav-cfn-byid-cs-")
    cs_created = cfn.create_change_set(
        StackName=stack_id, ChangeSetName=cs_name, ChangeSetType="UPDATE",
        TemplateBody=_TEMPLATE,
        Parameters=[{"ParameterKey": "ParamValue", "ParameterValue": "third"}],
    )
    assert cs_created["StackId"] == stack_id, (
        f"CreateChangeSet(StackName=<id>) returned StackId {cs_created['StackId']!r}, "
        f"expected {stack_id!r}"
    )
    cs_status = _wait_changeset(cfn, cs_created["Id"], stack_id)
    assert cs_status == "CREATE_COMPLETE", f"change set ended {cs_status!r}, expected CREATE_COMPLETE"
    described = cfn.describe_change_set(ChangeSetName=cs_created["Id"], StackName=stack_id)
    assert described["StackName"] == stack_name, (
        f"DescribeChangeSet resolved StackName {described['StackName']!r}, expected {stack_name!r}"
    )
    assert described["StackId"] == stack_id, "DescribeChangeSet's StackId diverged from the real id"

    cfn.execute_change_set(ChangeSetName=cs_created["Id"], StackName=stack_id)
    status = _wait_terminal(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"execute by id ended {status!r}, expected UPDATE_COMPLETE"
    assert ssm.get_parameter(Name=param_name)["Parameter"]["Value"] == "third", (
        "ExecuteChangeSet addressed by StackId did not change the parameter value"
    )


def _wait_terminal(cfn, stack_id, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in _TERMINAL:
            return status
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_id} did not reach terminal status within {timeout_s}s (last={status})")


def _wait_changeset(cfn, cs_id, stack_id, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cfn.describe_change_set(ChangeSetName=cs_id, StackName=stack_id)["Status"]
        if status in ("CREATE_COMPLETE", "FAILED"):
            return status
        time.sleep(interval_s)
    raise AssertionError(f"change set {cs_id} did not reach terminal status within {timeout_s}s (last={status})")


def _output(cfn, stack_id, key):
    outputs = cfn.describe_stacks(StackName=stack_id)["Stacks"][0].get("Outputs", [])
    for o in outputs:
        if o["OutputKey"] == key:
            return o["OutputValue"]
    raise AssertionError(f"no output {key!r} on stack {stack_id}; outputs were {outputs!r}")


def _delete_stack(cfn, stack_id):
    try:
        cfn.delete_stack(StackName=stack_id)
        deadline = time.monotonic() + 180.0
        while time.monotonic() < deadline:
            try:
                status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
            except ClientError as err:
                if not (
                    err.response["Error"]["Code"] == "ValidationError"
                    and "does not exist" in err.response["Error"].get("Message", "")
                ):
                    raise
                return
            if status == "DELETE_COMPLETE":
                return
            if status == "DELETE_FAILED":
                raise RuntimeError(f"stack {stack_id} DELETE_FAILED")
            time.sleep(3.0)
        raise RuntimeError(f"stack {stack_id} still deleting after 180s")
    except Exception as exc:  # noqa: BLE001 - re-raised
        raise RuntimeError(f"stack {stack_id}: {exc}") from exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
