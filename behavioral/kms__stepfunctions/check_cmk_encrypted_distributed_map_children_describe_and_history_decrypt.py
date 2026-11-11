"""cmk-encrypted-distributed-map-children-describe-and-history-decrypt."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cmk-encrypted-distributed-map-children-describe-and-history-decrypt"
GROUP = "cmk_encryption"
SERVICES = ["kms", "stepfunctions"]

_ITEMS = [{"id": f"c-{i}", "v": i * 3 + 1} for i in range(4)]
_REUSE_S = 60


@tags("axis:happy-path", "dp:api", "plane:data", "cap:c2", "cap:c3", "concern:e2e")
def run(ctx) -> None:
    """A Distributed Map's child executions run under the parent's CUSTOMER_MANAGED_KMS_KEY
    encryption: DescribeExecution and GetExecutionHistory decrypt each child's own input and
    output exactly, the same as a parent execution's.
    """
    sfn = ctx.client("stepfunctions")
    key = _key(ctx)
    role_arn = _role(ctx, key["Arn"])
    sm_arn = _state_machine(ctx, sfn, role_arn, key["Arn"])

    enc = sfn.describe_state_machine(stateMachineArn=sm_arn).get("encryptionConfiguration")
    assert enc == {"type": "CUSTOMER_MANAGED_KMS_KEY", "kmsKeyId": key["Arn"],
                   "kmsDataKeyReusePeriodSeconds": _REUSE_S}, (
        f"DescribeStateMachine must report the CMK configuration it was created with; got {enc!r}")

    exe = _run_to_terminal(ctx, sfn, sm_arn, {"items": _ITEMS})
    assert exe["status"] == "SUCCEEDED", (
        f"the CMK-encrypted parent execution must SUCCEED; got {exe['status']!r} "
        f"error={exe.get('error')!r} cause={exe.get('cause')!r}"
    )

    map_run = _one_map_run(sfn, exe["executionArn"])
    children = _list_executions(sfn, mapRunArn=map_run["mapRunArn"])
    child_arns = {c["executionArn"] for c in children}
    assert len(children) == len(_ITEMS) == len(child_arns), (
        f"ListExecutions(mapRunArn) must return one child per item under the CMK-encrypted "
        f"parent; got {len(children)} for {len(_ITEMS)} items"
    )
    assert {c["status"] for c in children} == {"SUCCEEDED"}, (
        f"every CMK-encrypted child must SUCCEED; statuses were "
        f"{sorted({c['status'] for c in children})!r}"
    )

    by_id = {}
    for arn in sorted(child_arns):
        desc = sfn.describe_execution(executionArn=arn)
        assert desc.get("mapRunArn") == map_run["mapRunArn"], (
            f"child {arn!r} DescribeExecution must name the map run; got {desc.get('mapRunArn')!r}"
        )
        inp = json.loads(desc["input"])
        out = json.loads(desc["output"])
        by_id[inp["id"]] = (inp, out)

        hist = _history(sfn, arn)
        types = [h["type"] for h in hist]
        assert types[0] == "ExecutionStarted" and types[-1] == "ExecutionSucceeded", (
            f"child {arn!r} history must run ExecutionStarted .. ExecutionSucceeded; got {types}"
        )
        assert json.loads(hist[0]["executionStartedEventDetails"]["input"]) == inp, (
            f"child {arn!r} GetExecutionHistory's ExecutionStarted input must equal "
            f"DescribeExecution's decrypted input; got "
            f"{hist[0]['executionStartedEventDetails'].get('input')!r} vs {desc['input']!r}"
        )

    expected = {it["id"]: ({"id": it["id"], "v": it["v"]}, {"id": it["id"], "doubled": it["v"] * 2})
                for it in _ITEMS}
    assert by_id == expected, (
        f"every child's decrypted (input, output) pair must match what it was given and "
        f"computed; got {by_id!r} != expected {expected!r}"
    )


# ===== helpers =====

_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
})

_DEFINITION = json.dumps({
    "StartAt": "Fan",
    "States": {
        "Fan": {
            "Type": "Map",
            "MaxConcurrency": len(_ITEMS),
            "ItemsPath": "$.items",
            "ItemSelector": {"id.$": "$$.Map.Item.Value.id", "v.$": "$$.Map.Item.Value.v"},
            "ItemProcessor": {
                "ProcessorConfig": {"Mode": "DISTRIBUTED", "ExecutionType": "STANDARD"},
                "StartAt": "Double",
                "States": {
                    "Double": {
                        "Type": "Pass",
                        "Parameters": {"id.$": "$.id", "doubled.$": "States.MathAdd($.v, $.v)"},
                        "End": True,
                    },
                },
            },
            "End": True,
        }
    },
})


def _key(ctx) -> dict:
    kms = ctx.client("kms")
    meta = kms.create_key(
        Description=f"sim2real-behav-sfncmk-dmap {CHECK[:170]}",
        KeyUsage="ENCRYPT_DECRYPT",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK[:250]}],
    )["KeyMetadata"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=meta["KeyId"], PendingWindowInDays=7))
    return meta


def _role(ctx, key_arn: str) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfncmk-dmap-role-")
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=_TRUST, Path="/sim2real/",
        Description="sim2real-behav: sfn CMK distributed-map execution role",
        Tags=[{"Key": "sim2real", "Value": CHECK[:250]}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    statements = [
        {"Effect": "Allow", "Action": ["kms:Decrypt", "kms:GenerateDataKey"], "Resource": key_arn},
        {"Effect": "Allow", "Action": "states:StartExecution",
         "Resource": f"arn:aws:states:{ctx.region}:{ctx.account}:stateMachine:*"},
        {"Effect": "Allow", "Action": ["states:DescribeExecution", "states:StopExecution"],
         "Resource": f"arn:aws:states:{ctx.region}:{ctx.account}:execution:*:*"},
    ]
    iam.put_role_policy(
        RoleName=name, PolicyName="inline",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"))
    return arn


def _state_machine(ctx, sfn, role_arn: str, key_arn: str) -> str:
    name = ctx.unique_name("sim2real-behav-sfncmk-dmap-")
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
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(2.0)
            continue
        ctx.on_cleanup(lambda a=arn: sfn.delete_state_machine(stateMachineArn=a))
        return arn
    raise AssertionError(f"CreateStateMachine still AccessDenied after 150s: {last!r}")


_PROPAGATION_MARKERS = (
    "KmsAccessDeniedException", "not authorized to assume", "AccessDenied",
    "security token included in the request is invalid",
)


def _run_to_terminal(ctx, sfn, sm_arn: str, extra_input: dict, *, timeout_s: float = 300.0,
                     propagation_s: float = 150.0) -> dict:
    """Start an execution under a fresh name and poll it to terminal, retrying a whole fresh
    execution only while the freshly created role's or key's permissions are still
    propagating (the state machine's own trust, its CMK grants, or the Map's own
    states:StartExecution on itself)."""
    deadline = time.monotonic() + propagation_s
    while True:
        try:
            exec_arn = sfn.start_execution(
                stateMachineArn=sm_arn, name=ctx.unique_name("sim2real-behav-exec-"),
                input=json.dumps(extra_input),
            )["executionArn"]
        except ClientError as exc:
            blob = exc.response["Error"].get("Message", "") + exc.response["Error"]["Code"]
            if not any(m in blob for m in _PROPAGATION_MARKERS) or time.monotonic() >= deadline:
                raise
            time.sleep(2.0)
            continue
        ctx.on_cleanup(lambda a=exec_arn: _best_effort_stop(ctx, a))
        desc = _wait_terminal(ctx, sfn, exec_arn, timeout_s=timeout_s)
        blob = (desc.get("cause") or "") + (desc.get("error") or "")
        if desc["status"] != "FAILED" or not any(m in blob for m in _PROPAGATION_MARKERS):
            return desc
        if time.monotonic() >= deadline:
            return desc
        time.sleep(2.0)


def _wait_terminal(ctx, sfn, exec_arn: str, *, timeout_s: float, interval_s: float = 2.0) -> dict:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] != "RUNNING":
            return last
        time.sleep(interval_s)
    raise AssertionError(f"execution {exec_arn} was not terminal within {timeout_s}s: {last!r}")


def _best_effort_stop(ctx, exec_arn: str) -> None:
    sfn = ctx.client("stepfunctions")
    try:
        if sfn.describe_execution(executionArn=exec_arn)["status"] == "RUNNING":
            sfn.stop_execution(executionArn=exec_arn, error="cleanup", cause="sim2real cleanup")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
            raise


def _one_map_run(sfn, exec_arn: str) -> dict:
    runs, token = [], None
    while True:
        kwargs = {"executionArn": exec_arn, "maxResults": 100}
        if token:
            kwargs["nextToken"] = token
        resp = sfn.list_map_runs(**kwargs)
        runs.extend(resp["mapRuns"])
        token = resp.get("nextToken")
        if not token:
            break
    assert len(runs) == 1, f"expected exactly one map run for {exec_arn!r}, got {runs!r}"
    return runs[0]


def _list_executions(sfn, **filters) -> list[dict]:
    out, token = [], None
    while True:
        kwargs = {"maxResults": 100, **filters}
        if token:
            kwargs["nextToken"] = token
        resp = sfn.list_executions(**kwargs)
        out.extend(resp["executions"])
        token = resp.get("nextToken")
        if not token:
            return out


def _history(sfn, exec_arn: str) -> list[dict]:
    events = []
    for page in sfn.get_paginator("get_execution_history").paginate(executionArn=exec_arn):
        events.extend(page.get("events") or [])
    return events


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
