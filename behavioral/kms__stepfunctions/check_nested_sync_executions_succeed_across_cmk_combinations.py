"""nested-sync-executions-succeed-across-cmk-combinations."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "nested-sync-executions-succeed-across-cmk-combinations"
GROUP = "cmk_encryption"
SERVICES = ["kms", "stepfunctions"]

_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
})

_CHILD_DEFINITION = json.dumps({
    "StartAt": "Shape",
    "States": {
        "Shape": {
            "Type": "Pass",
            "Parameters": {"value.$": "States.Format('{}-child', $.seed)"},
            "End": True,
        },
    },
})

_PARENT_DEFINITION = json.dumps({
    "StartAt": "CallChild",
    "States": {
        "CallChild": {
            "Type": "Task",
            "Resource": "arn:aws:states:::states:startExecution.sync:2",
            "Parameters": {"StateMachineArn.$": "$.childArn", "Input": {"seed.$": "$.seed"}},
            "ResultSelector": {"fromChild.$": "$.Output.value"},
            "End": True,
        },
    },
})

_MAP_ITEMS = [{"id": "x"}, {"id": "y"}, {"id": "z"}]
_MAP_DEFINITION = json.dumps({
    "StartAt": "Fan",
    "States": {
        "Fan": {
            "Type": "Map",
            "ItemsPath": "$.items",
            "ItemProcessor": {
                "ProcessorConfig": {"Mode": "DISTRIBUTED", "ExecutionType": "STANDARD"},
                "StartAt": "Tag",
                "States": {
                    "Tag": {
                        "Type": "Pass",
                        "Parameters": {"id.$": "$.id", "tagged.$": "States.Format('{}-done', $.id)"},
                        "End": True,
                    },
                },
            },
            "MaxConcurrency": 3,
            "End": True,
        },
    },
})


def _key(ctx) -> dict:
    kms = ctx.client("kms")
    meta = kms.create_key(
        Description=f"sim2real-xsvc-sfn3 {CHECK[:200]}", KeyUsage="ENCRYPT_DECRYPT",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK[:250]}],
    )["KeyMetadata"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=meta["KeyId"], PendingWindowInDays=7))
    return meta


def _exec_role(ctx, key_arns: list[str]) -> str:
    iam = ctx.client("iam")
    region, account = ctx.region, ctx.account
    name = ctx.unique_name("sim2real-xsvc-sfn3-nest-")[:64]
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=_TRUST, Path="/sim2real/",
        Description="sim2real-xsvc: sfn nested-CMK execution role",
        Tags=[{"Key": "sim2real", "Value": CHECK[:250]}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    statements = [
        {"Effect": "Allow", "Action": ["kms:GenerateDataKey", "kms:Decrypt"], "Resource": key_arns},
        {"Effect": "Allow", "Action": "states:StartExecution",
         "Resource": f"arn:aws:states:{region}:{account}:stateMachine:*"},
        {"Effect": "Allow", "Action": ["states:DescribeExecution", "states:StopExecution"],
         "Resource": f"arn:aws:states:{region}:{account}:execution:*:*"},
        {"Effect": "Allow",
         "Action": ["events:PutTargets", "events:PutRule", "events:DescribeRule"],
         "Resource": (f"arn:aws:events:{region}:{account}:rule/"
                      "StepFunctionsGetEventsForStepFunctionsExecutionRule")},
    ]
    iam.put_role_policy(
        RoleName=name, PolicyName="perms",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="perms"))
    return arn


def _create_state_machine(ctx, definition: str, role_arn: str, *, key_arn: str | None = None,
                          deadline_s: float = 150.0) -> str:
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-xsvc-sfn3-nest-")[:80]
    kwargs = dict(name=name, definition=definition, roleArn=role_arn, type="STANDARD",
                 tags=[{"key": "sim2real", "value": CHECK[:250]}])
    if key_arn is not None:
        kwargs["encryptionConfiguration"] = {
            "type": "CUSTOMER_MANAGED_KMS_KEY", "kmsKeyId": key_arn,
            "kmsDataKeyReusePeriodSeconds": 60,
        }
    deadline = time.monotonic() + deadline_s
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(**kwargs)["stateMachineArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(5.0)
            continue
        ctx.on_cleanup(lambda a=arn: sfn.delete_state_machine(stateMachineArn=a))
        return arn
    raise AssertionError(f"CreateStateMachine {name!r} still AccessDenied after {deadline_s}s: {last}")


_TRUST_RACE_MARKERS = ("KmsAccessDeniedException", "not authorized to assume", "AccessDeniedException")


def _run_to_terminal(ctx, sm_arn: str, payload: dict, *, deadline_s: float = 150.0) -> dict:
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + deadline_s
    desc = None
    while time.monotonic() < deadline:
        exec_arn = sfn.start_execution(
            stateMachineArn=sm_arn, name=ctx.unique_name("sim2real-xsvc-sfn3-nest-exec-"),
            input=json.dumps(payload),
        )["executionArn"]
        ctx.on_cleanup(lambda a=exec_arn: _best_effort_stop(ctx, a))
        desc = _wait_terminal(ctx, exec_arn, timeout_s=120.0)
        blob = (desc.get("cause") or "") + (desc.get("error") or "")
        if desc["status"] != "FAILED" or not any(m in blob for m in _TRUST_RACE_MARKERS):
            return desc
        time.sleep(5.0)
    raise AssertionError(f"execution of {sm_arn!r} never got past propagation: {desc!r}")


def _wait_terminal(ctx, exec_arn: str, *, timeout_s: float = 120.0) -> dict:
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] != "RUNNING":
            return last
        time.sleep(2.0)
    raise AssertionError(f"execution {exec_arn} still RUNNING after {timeout_s}s: {last!r}")


def _best_effort_stop(ctx, exec_arn: str) -> None:
    sfn = ctx.client("stepfunctions")
    try:
        if sfn.describe_execution(executionArn=exec_arn)["status"] == "RUNNING":
            sfn.stop_execution(executionArn=exec_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
            raise


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A nested .sync:2 execution SUCCEEDs with the parent, the child, or both CMK-encrypted
    (even under different keys), and a Distributed Map of child executions on a CMK-encrypted
    machine completes and is describable with includedData=ALL_DATA.
    """
    key_a = _key(ctx)
    key_b = _key(ctx)
    role_arn = _exec_role(ctx, [key_a["Arn"], key_b["Arn"]])

    child_plain = _create_state_machine(ctx, _CHILD_DEFINITION, role_arn)
    child_cmk_a = _create_state_machine(ctx, _CHILD_DEFINITION, role_arn, key_arn=key_a["Arn"])
    parent_plain = _create_state_machine(ctx, _PARENT_DEFINITION, role_arn)
    parent_cmk_b = _create_state_machine(ctx, _PARENT_DEFINITION, role_arn, key_arn=key_b["Arn"])

    combos = (
        ("parent-default,child-cmk", parent_plain, child_cmk_a),
        ("parent-cmk,child-default", parent_cmk_b, child_plain),
        ("parent-cmk,child-cmk", parent_cmk_b, child_cmk_a),
    )
    for label, parent_arn, child_arn in combos:
        seed = ctx.unique_name(f"sim2real-seed-{label}-")
        desc = _run_to_terminal(ctx, parent_arn, {"childArn": child_arn, "seed": seed})
        assert desc["status"] == "SUCCEEDED", (
            f"[{label}] a nested .sync:2 execution across this CMK combination must SUCCEED; "
            f"got {desc['status']!r} error={desc.get('error')!r} cause={desc.get('cause')!r}")
        out = json.loads(desc["output"])
        assert out == {"fromChild": f"{seed}-child"}, (
            f"[{label}] the nested child's output must reach the parent; got {out!r}")

    map_sm = _create_state_machine(ctx, _MAP_DEFINITION, role_arn, key_arn=key_b["Arn"])
    map_desc = _run_to_terminal(ctx, map_sm, {"items": _MAP_ITEMS}, deadline_s=200.0)
    assert map_desc["status"] == "SUCCEEDED", (
        f"a Distributed Map of child executions on a CMK-encrypted machine must SUCCEED; got "
        f"{map_desc['status']!r} error={map_desc.get('error')!r} cause={map_desc.get('cause')!r}")

    sfn = ctx.client("stepfunctions")
    full = sfn.describe_execution(executionArn=map_desc["executionArn"], includedData="ALL_DATA")
    assert json.loads(full["input"]) == {"items": _MAP_ITEMS}, (
        f"DescribeExecution(includedData=ALL_DATA) on a CMK Distributed Map must return the "
        f"real input; got {full.get('input')!r}")
    assert json.loads(full["output"]) == [{"id": i["id"], "tagged": f"{i['id']}-done"}
                                          for i in _MAP_ITEMS], (
        f"DescribeExecution(includedData=ALL_DATA) must return the real, per-item output; got "
        f"{full.get('output')!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
