"""xsvc-sfn-cmk-context-object-inputpath-outputpath-choice-and-map-itemspath-unchanged."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-sfn-cmk-context-object-inputpath-outputpath-choice-and-map-itemspath-unchanged"
GROUP = "cmk_encryption"
SERVICES = ["kms", "stepfunctions"]

_ITEMS = ["a", "b", "c"]


@tags("axis:happy-path", "dp:api", "plane:data", "cap:c3", "concern:data-plane")
def run(ctx) -> None:
    """On a CMK-encrypted state machine, InputPath, the Context object ($$.Execution.Name),
    a Choice rule's Variable resolved against the context object, a Map's ItemsPath and its
    ItemSelector's $$.Map.Item fields, and OutputPath all resolve exactly as documented."""
    sfn = ctx.client("stepfunctions")
    key = _key(ctx)
    _role_name, role_arn = _exec_role(ctx, key["Arn"])
    sm_arn = _state_machine(ctx, role_arn, key["Arn"])

    marker = ctx.unique_name("sim2real-mark-")
    payload = json.dumps({"payload": {"marker": marker, "items": _ITEMS}})
    exec_arn = _start(ctx, sm_arn, payload)
    desc = _wait_terminal(ctx, exec_arn)
    assert desc["status"] == "SUCCEEDED", (
        f"the CMK-encrypted execution must SUCCEED; got {desc['status']!r} "
        f"error={desc.get('error')!r} cause={desc.get('cause')!r}")

    exec_name = exec_arn.rsplit(":", 1)[-1]
    output = json.loads(desc["output"])
    assert output == [{"idx": i, "value": v} for i, v in enumerate(_ITEMS)], (
        "the Map's ItemSelector must build each item from $$.Map.Item.Index/.Value, and "
        f"OutputPath must select only the Map's result; got {output!r}")

    events = _history(ctx, exec_arn)
    shape_exit = _only(events, "Shape")
    assert json.loads(shape_exit) == {"marker": marker, "items": _ITEMS, "execName": exec_name}, (
        "InputPath must narrow to $.payload and Parameters must resolve $$.Execution.Name "
        f"to the execution's own name {exec_name!r}; the Shape state exited with "
        f"{shape_exit!r}")

    choose_entered = [e for e in events
                      if e.get("stateEnteredEventDetails", {}).get("name") == "Choose"]
    assert len(choose_entered) == 1, (
        f"the Choose state must be entered exactly once; got {len(choose_entered)}")
    fail_events = [e for e in events if e["type"] == "ExecutionFailed"]
    assert fail_events == [], (
        "a Choice rule whose Variable is $$.State.Name must select the matching branch, "
        f"never the Default (which this definition routes to a Fail state); got "
        f"{fail_events!r}")

    map_started = [e for e in events if e["type"] == "MapIterationStarted"]
    assert len(map_started) == len(_ITEMS), (
        f"the Map must run one iteration per ItemsPath element ({len(_ITEMS)}); got "
        f"{len(map_started)}")


_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
})

_DEFINITION = json.dumps({
    "StartAt": "Shape",
    "States": {
        "Shape": {
            "Type": "Pass",
            "InputPath": "$.payload",
            "Parameters": {"marker.$": "$.marker", "items.$": "$.items",
                            "execName.$": "$$.Execution.Name"},
            "Next": "Choose",
        },
        "Choose": {
            "Type": "Choice",
            "Choices": [{"Variable": "$$.State.Name", "StringEquals": "Choose",
                         "Next": "IterateMap"}],
            "Default": "WrongBranch",
        },
        "WrongBranch": {"Type": "Fail", "Error": "WrongBranch"},
        "IterateMap": {
            "Type": "Map",
            "ItemsPath": "$.items",
            "ItemSelector": {"idx.$": "$$.Map.Item.Index", "value.$": "$$.Map.Item.Value"},
            "ItemProcessor": {
                "ProcessorConfig": {"Mode": "INLINE"},
                "StartAt": "Tag",
                "States": {
                    "Tag": {"Type": "Pass",
                            "Parameters": {"idx.$": "$.idx", "value.$": "$.value"},
                            "End": True},
                },
            },
            "ResultPath": "$.processed",
            "OutputPath": "$.processed",
            "End": True,
        },
    },
})

_REUSE_S = 60


def _key(ctx) -> dict:
    kms = ctx.client("kms")
    account = ctx.account
    pol = {"Version": "2012-10-17", "Statement": [
        {"Sid": "root", "Effect": "Allow",
         "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
         "Action": "kms:*", "Resource": "*"},
    ]}
    meta = kms.create_key(
        Description=f"sim2real-behav-sfn-cmk-context {CHECK[:130]}",
        KeyUsage="ENCRYPT_DECRYPT", Policy=json.dumps(pol),
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK[:250]}],
    )["KeyMetadata"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=meta["KeyId"], PendingWindowInDays=7))
    return meta


def _exec_role(ctx, key_arn: str) -> tuple[str, str]:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfn-ctx-exec-")[:64]
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=_TRUST, Path="/sim2real/",
        Description="sim2real: sfn context-object CMK execution role",
        Tags=[{"Key": "sim2real", "Value": CHECK[:250]}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(
        RoleName=name, PolicyName="kms",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": ["kms:Decrypt", "kms:GenerateDataKey"],
             "Resource": key_arn}]}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="kms"))
    return name, arn


def _state_machine(ctx, role_arn: str, key_arn: str) -> str:
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfn-ctx-cmk-sm-")[:80]
    deadline = time.monotonic() + 150.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=_DEFINITION, roleArn=role_arn, type="STANDARD",
                encryptionConfiguration={
                    "type": "CUSTOMER_MANAGED_KMS_KEY", "kmsKeyId": key_arn,
                    "kmsDataKeyReusePeriodSeconds": _REUSE_S,
                },
                tags=[{"key": "sim2real", "value": CHECK[:250]}],
            )["stateMachineArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("AccessDeniedException",
                                                       "KmsAccessDeniedException"):
                raise
            last = exc
            time.sleep(5.0)
            continue
        ctx.on_cleanup(lambda a=arn: sfn.delete_state_machine(stateMachineArn=a))
        return arn
    raise AssertionError(f"CreateStateMachine still denied after 150s: {last}")


def _start(ctx, sm_arn: str, payload: str) -> str:
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + 150.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.start_execution(stateMachineArn=sm_arn, input=payload)["executionArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "KmsAccessDeniedException":
                raise
            last = exc
            time.sleep(4.0)
            continue
        ctx.on_cleanup(lambda: _stop_if_running(sfn, arn))
        return arn
    raise AssertionError(f"StartExecution still KmsAccessDenied after 150s: {last}")


def _stop_if_running(sfn, arn: str) -> None:
    if sfn.describe_execution(executionArn=arn)["status"] == "RUNNING":
        sfn.stop_execution(executionArn=arn)


def _wait_terminal(ctx, exec_arn: str) -> dict:
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + 90.0
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] != "RUNNING":
            return last
        time.sleep(2.0)
    raise AssertionError(f"execution still RUNNING after 90s: {last!r}")


def _history(ctx, exec_arn: str) -> list[dict]:
    sfn = ctx.client("stepfunctions")
    out, kwargs = [], {"executionArn": exec_arn, "maxResults": 1000}
    while True:
        resp = sfn.get_execution_history(**kwargs)
        out.extend(resp["events"])
        if not resp.get("nextToken"):
            return out
        kwargs["nextToken"] = resp["nextToken"]


def _only(events: list[dict], state_name: str) -> str:
    matching = [e for e in events
               if e.get("stateExitedEventDetails", {}).get("name") == state_name]
    assert len(matching) == 1, (
        f"history must record {state_name!r} exited exactly once; got {len(matching)}")
    return matching[0]["stateExitedEventDetails"]["output"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
