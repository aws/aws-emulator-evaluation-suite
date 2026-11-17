"""cfn-state-machine-encryption-configuration-round-trips-and-updates-in-place."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-state-machine-encryption-configuration-round-trips-and-updates-in-place"
GROUP = "deploy"
SERVICES = ["cloudformation", "kms", "stepfunctions"]

_DEFINITION = {"StartAt": "Hello", "States": {"Hello": {"Type": "Pass", "Result": {"ok": True}, "End": True}}}

_STACK_CAP_S = 600.0
_EXECUTION_CAP_S = 120.0
_POLL_S = 2.0


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _poll(probe, predicate, *, timeout_s: float, interval_s: float = _POLL_S, what: str = "condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what} not met within {timeout_s:.0f}s; last={last!r}")
        time.sleep(interval_s)


def _template(sm_name: str, role_name: str, kms_key_id: str, reuse_period: int,
               kms_key_arns: list[str]) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "ExecRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": role_name,
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "states.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }],
                    },
                    "Policies": [{
                        "PolicyName": "UseEncryptionKeys",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [{
                                "Effect": "Allow",
                                "Action": ["kms:GenerateDataKey", "kms:Decrypt", "kms:DescribeKey"],
                                "Resource": kms_key_arns,
                            }],
                        },
                    }],
                },
            },
            "MyStateMachine": {
                "Type": "AWS::StepFunctions::StateMachine",
                "Properties": {
                    "StateMachineName": sm_name,
                    "StateMachineType": "STANDARD",
                    "RoleArn": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                    "DefinitionString": json.dumps(_DEFINITION),
                    "EncryptionConfiguration": {
                        "Type": "CUSTOMER_MANAGED_KMS_KEY",
                        "KmsKeyId": kms_key_id,
                        "KmsDataKeyReusePeriodSeconds": reuse_period,
                    },
                },
            },
        },
        "Outputs": {
            "RoleArn": {"Value": {"Fn::GetAtt": ["ExecRole", "Arn"]}},
            "StateMachineArn": {"Value": {"Ref": "MyStateMachine"}},
        },
    })


def _settle(cfn, stack_id: str, timeout_s: float = _STACK_CAP_S) -> dict:
    """Poll DescribeStacks by StackId until the stack leaves every *_IN_PROGRESS status."""
    return _poll(
        lambda: cfn.describe_stacks(StackName=stack_id)["Stacks"][0],
        lambda s: not s["StackStatus"].endswith("_IN_PROGRESS"),
        timeout_s=timeout_s, what=f"stack {stack_id} settling",
    )


def _expect(cfn, stack: dict, want: str) -> None:
    if stack["StackStatus"] == want:
        return
    events = cfn.get_paginator("describe_stack_events").paginate(StackName=stack["StackId"])
    failed = [
        (e["LogicalResourceId"], e["ResourceStatus"], e.get("ResourceStatusReason"))
        for page in events for e in page["StackEvents"] if e["ResourceStatus"].endswith("_FAILED")
    ]
    raise AssertionError(f"stack ended {stack['StackStatus']!r}, expected {want!r}; failed: {failed!r}")


def _outputs(cfn, stack_id: str) -> dict[str, str]:
    stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _machine_events(cfn, stack_id: str, seen: set[str]) -> list[tuple]:
    """(status, physical id) of MyStateMachine's events not yet in *seen*, oldest first."""
    pages = cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id)
    rows = [
        (e["EventId"], e["ResourceStatus"], e.get("PhysicalResourceId"))
        for page in pages for e in page["StackEvents"]
        if e["LogicalResourceId"] == "MyStateMachine" and e["EventId"] not in seen
    ]
    return list(reversed(rows))


def _assert_execution_succeeds(ctx, sfn, arn: str) -> None:
    """Start an execution and poll it to a terminal state; it must SUCCEED with the Pass result.

    The exec role's grant on the active encryption key can still be propagating through IAM, so
    StartExecution is retried on KmsAccessDeniedException within a bounded deadline.
    """
    deadline = time.monotonic() + 90.0
    while True:
        try:
            exec_arn = sfn.start_execution(
                stateMachineArn=arn, name=ctx.unique_name("sim2real-run-"), input="{}",
            )["executionArn"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "KmsAccessDeniedException":
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"StartExecution on {arn} still KmsAccessDeniedException after 90s"
                ) from exc
            time.sleep(3.0)
    described = _poll(
        lambda: sfn.describe_execution(executionArn=exec_arn),
        lambda d: d["status"] != "RUNNING",
        timeout_s=_EXECUTION_CAP_S, what=f"execution {exec_arn} leaving RUNNING",
    )
    assert described["status"] == "SUCCEEDED", f"execution {exec_arn} ended {described!r}"
    assert json.loads(described["output"]) == {"ok": True}, (
        f"execution {exec_arn} output {described['output']!r}, expected the Pass result"
    )


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control",
      "plane:data", "dp:api")
def run(ctx) -> None:
    """A CFN-deployed AWS::StepFunctions::StateMachine with a customer managed KMS key describes
    with the template's EncryptionConfiguration, runs an execution, updates the key and the data
    key reuse period in place with no replacement, and the stack delete leaves the KMS keys intact.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-stepfunctions-statemachine.html
    https://docs.aws.amazon.com/step-functions/latest/dg/encryption-at-rest.html
    """
    cfn, kms, sfn = ctx.client("cloudformation"), ctx.client("kms"), ctx.client("stepfunctions")

    key_a = kms.create_key(
        Description="sim2real-behav-sfn-cmk-a", KeyUsage="ENCRYPT_DECRYPT", KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_a["KeyId"], PendingWindowInDays=7))
    key_b = kms.create_key(
        Description="sim2real-behav-sfn-cmk-b", KeyUsage="ENCRYPT_DECRYPT", KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_b["KeyId"], PendingWindowInDays=7))

    stack_name = ctx.unique_name("sim2real-behav-sfnenc-stack-")
    sm_name = ctx.unique_name("sim2real-behav-sfnenc-sm-")
    role_name = ctx.unique_name("sim2real-behav-sfnenc-role-")

    stack_id = {"value": None}
    ctx.on_cleanup(lambda: _teardown_stack(cfn, stack_name, stack_id))

    stack_id["value"] = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(sm_name, role_name, key_a["Arn"], 60, [key_a["Arn"], key_b["Arn"]]),
        Capabilities=["CAPABILITY_NAMED_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    stack = _settle(cfn, stack_id["value"])
    _expect(cfn, stack, "CREATE_COMPLETE")
    outputs = _outputs(cfn, stack_id["value"])
    arn = outputs["StateMachineArn"]

    desc = sfn.describe_state_machine(stateMachineArn=arn)
    assert desc["name"] == sm_name, f"expected name {sm_name!r}, got {desc['name']!r}"
    assert desc["status"] == "ACTIVE", f"expected status ACTIVE, got {desc['status']!r}"
    want_enc = {"type": "CUSTOMER_MANAGED_KMS_KEY", "kmsKeyId": key_a["Arn"],
                "kmsDataKeyReusePeriodSeconds": 60}
    assert desc["encryptionConfiguration"] == want_enc, (
        f"expected encryptionConfiguration {want_enc!r}, got {desc['encryptionConfiguration']!r}"
    )
    _assert_execution_succeeds(ctx, sfn, arn)

    # ---- in-place update: swap the key and raise the data key reuse period
    seen = {eid for eid, _, _ in _machine_events(cfn, stack_id["value"], set())}
    cfn.update_stack(
        StackName=stack_id["value"],
        TemplateBody=_template(sm_name, role_name, key_b["Arn"], 900, [key_a["Arn"], key_b["Arn"]]),
        Capabilities=["CAPABILITY_NAMED_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    stack = _settle(cfn, stack_id["value"])
    _expect(cfn, stack, "UPDATE_COMPLETE")
    rows = _machine_events(cfn, stack_id["value"], seen)
    statuses = [status for _, status, _ in rows]
    assert statuses == ["UPDATE_IN_PROGRESS", "UPDATE_COMPLETE"], (
        f"EncryptionConfiguration is not createOnly and must update in place with no replacement, "
        f"its events were {rows!r}"
    )
    assert rows[-1][2] == arn, f"the update must complete on the same physical id {arn!r}, got {rows!r}"

    desc_after = sfn.describe_state_machine(stateMachineArn=arn)
    assert desc_after["stateMachineArn"] == arn, (
        f"the state machine's ARN must stay {arn!r} after an in-place update, got "
        f"{desc_after['stateMachineArn']!r}"
    )
    want_enc_after = {"type": "CUSTOMER_MANAGED_KMS_KEY", "kmsKeyId": key_b["Arn"],
                      "kmsDataKeyReusePeriodSeconds": 900}
    assert desc_after["encryptionConfiguration"] == want_enc_after, (
        f"expected encryptionConfiguration {want_enc_after!r} after the update, got "
        f"{desc_after['encryptionConfiguration']!r}"
    )
    _assert_execution_succeeds(ctx, sfn, arn)

    # ---- delete: the state machine and its role are gone, the KMS keys the stack never owned stay
    cfn.delete_stack(StackName=stack_id["value"])
    stack = _settle(cfn, stack_id["value"])
    _expect(cfn, stack, "DELETE_COMPLETE")

    code, message = _poll(
        lambda: _error(lambda: sfn.describe_state_machine(stateMachineArn=arn)),
        lambda r: r[0] is not None, timeout_s=120.0, what=f"{arn} describing as gone",
    )
    assert code == "StateMachineDoesNotExist", f"expected StateMachineDoesNotExist, got {code!r}"
    expected_message = f"State Machine Does Not Exist: '{arn}'"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    role_error = _error(lambda: ctx.client("iam").get_role(RoleName=role_name))
    assert role_error == ("NoSuchEntity", f"The role with name {role_name} cannot be found."), (
        f"GetRole on the stack's role after the delete: {role_error!r}"
    )

    for key in (key_a, key_b):
        state = kms.describe_key(KeyId=key["KeyId"])["KeyMetadata"]["KeyState"]
        assert state == "Enabled", (
            f"the stack never owned KMS key {key['KeyId']!r}; deleting it must leave the key "
            f"Enabled, got {state!r}"
        )


def _teardown_stack(cfn, stack_name: str, stack_id: dict) -> None:
    """Delete the stack by its id once known, else by name; a stack that never existed is done."""
    name = stack_id["value"] or stack_name
    try:
        current = cfn.describe_stacks(StackName=name)["Stacks"][0]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ValidationError":
            raise
        return
    if current["StackStatus"] == "DELETE_COMPLETE":
        return
    if current["StackStatus"].endswith("_IN_PROGRESS"):
        current = _settle(cfn, current["StackId"])
    if current["StackStatus"] != "DELETE_COMPLETE":
        cfn.delete_stack(StackName=current["StackId"])
        current = _settle(cfn, current["StackId"])
    _expect(cfn, current, "DELETE_COMPLETE")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
