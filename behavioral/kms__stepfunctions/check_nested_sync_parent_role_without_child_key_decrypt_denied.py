"""nested-sync-parent-role-without-child-key-decrypt-denied."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "nested-sync-parent-role-without-child-key-decrypt-denied"
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


def _key(ctx) -> dict:
    kms = ctx.client("kms")
    meta = kms.create_key(
        Description=f"sim2real-xsvc-sfn3 {CHECK[:200]}", KeyUsage="ENCRYPT_DECRYPT",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK[:250]}],
    )["KeyMetadata"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=meta["KeyId"], PendingWindowInDays=7))
    return meta


def _role(ctx, statements: list[dict]) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-xsvc-sfn3-pnd-")[:64]
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=_TRUST, Path="/sim2real/",
        Description="sim2real-xsvc: sfn nested-CMK role under test",
        Tags=[{"Key": "sim2real", "Value": CHECK[:250]}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(
        RoleName=name, PolicyName="perms",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="perms"))
    return arn


def _sync_perms(region: str, account: str) -> list[dict]:
    return [
        {"Effect": "Allow", "Action": "states:StartExecution",
         "Resource": f"arn:aws:states:{region}:{account}:stateMachine:*"},
        {"Effect": "Allow", "Action": ["states:DescribeExecution", "states:StopExecution"],
         "Resource": f"arn:aws:states:{region}:{account}:execution:*:*"},
        {"Effect": "Allow",
         "Action": ["events:PutTargets", "events:PutRule", "events:DescribeRule"],
         "Resource": (f"arn:aws:events:{region}:{account}:rule/"
                      "StepFunctionsGetEventsForStepFunctionsExecutionRule")},
    ]


def _create_state_machine(ctx, definition: str, role_arn: str, *, key_arn: str | None = None,
                          deadline_s: float = 150.0) -> str:
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-xsvc-sfn3-pnd-")[:80]
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


_TRUST_RACE_MARKERS = ("not authorized to assume", "AccessDeniedException")
_ASSUME_RACE_MARKER = "not authorized to assume"


def _run_once(ctx, sm_arn: str, payload: dict) -> dict:
    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(
        stateMachineArn=sm_arn, name=ctx.unique_name("sim2real-xsvc-sfn3-pnd-exec-"),
        input=json.dumps(payload),
    )["executionArn"]
    ctx.on_cleanup(lambda: _best_effort_stop(ctx, exec_arn))
    return _wait_terminal(ctx, exec_arn, timeout_s=120.0)


def _run_control_past_propagation(ctx, sm_arn: str, payload: dict, *,
                                  deadline_s: float = 150.0) -> dict:
    deadline = time.monotonic() + deadline_s
    desc = None
    while time.monotonic() < deadline:
        desc = _run_once(ctx, sm_arn, payload)
        blob = (desc.get("cause") or "") + (desc.get("error") or "")
        if desc["status"] != "FAILED" or not any(m in blob for m in _TRUST_RACE_MARKERS):
            return desc
        time.sleep(5.0)
    raise AssertionError(f"control execution of {sm_arn!r} never got past propagation: {desc!r}")


def _run_denied_past_propagation(ctx, sm_arn: str, payload: dict, *,
                                 deadline_s: float = 150.0) -> dict:
    deadline = time.monotonic() + deadline_s
    desc = None
    while time.monotonic() < deadline:
        desc = _run_once(ctx, sm_arn, payload)
        if desc["status"] != "FAILED" or _ASSUME_RACE_MARKER not in (desc.get("cause") or ""):
            return desc
        time.sleep(5.0)
    raise AssertionError(f"denied execution of {sm_arn!r} never got past propagation: {desc!r}")


def _stable_session(message: str | None, role_name: str) -> str | None:
    if message is None:
        return None
    pattern = re.compile(rf"(assumed-role/{re.escape(role_name)}/)[^ ]+")
    return pattern.sub(r"\1<session>", message, count=1)


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


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A parent's nested .sync:2 execution FAILS when its own role lacks kms:Decrypt on the
    CMK-encrypted child's key -- it cannot read back the child's output -- while a twin parent
    role holding that grant succeeds on the identical wiring.
    """
    region, account = ctx.region, ctx.account
    child_key = _key(ctx)

    child_role = _role(ctx, [
        {"Effect": "Allow", "Action": ["kms:GenerateDataKey", "kms:Decrypt"],
         "Resource": child_key["Arn"]},
    ])
    child_arn = _create_state_machine(ctx, _CHILD_DEFINITION, child_role, key_arn=child_key["Arn"])

    good_parent_role = _role(ctx, _sync_perms(region, account) + [
        {"Effect": "Allow", "Action": "kms:Decrypt", "Resource": child_key["Arn"]}])
    bad_parent_role = _role(ctx, _sync_perms(region, account))

    good_parent = _create_state_machine(ctx, _PARENT_DEFINITION, good_parent_role)
    bad_parent = _create_state_machine(ctx, _PARENT_DEFINITION, bad_parent_role)

    good_seed = ctx.unique_name("sim2real-seed-good-")
    good = _run_control_past_propagation(
        ctx, good_parent, {"childArn": child_arn, "seed": good_seed})
    assert good["status"] == "SUCCEEDED", (
        f"control: a parent role holding kms:Decrypt on the child's key must SUCCEED; got "
        f"{good['status']!r} error={good.get('error')!r} cause={good.get('cause')!r}")
    out = json.loads(good["output"])
    assert out == {"fromChild": f"{good_seed}-child"}, (
        f"control: the child's output must reach the parent; got {out!r}")

    bad_role_name = bad_parent_role.rsplit("/", 1)[-1]
    denial = (
        f"User: arn:aws:sts::{account}:assumed-role/{bad_role_name}/<session> is not authorized "
        f"to perform: kms:Decrypt on resource: {child_key['Arn']} because no identity-based "
        "policy allows the kms:Decrypt action"
    )
    for _ in range(3):
        bad_seed = ctx.unique_name("sim2real-seed-bad-")
        bad = _run_denied_past_propagation(
            ctx, bad_parent, {"childArn": child_arn, "seed": bad_seed})
        assert bad["status"] == "FAILED", (
            f"a parent role lacking kms:Decrypt on the child's key must FAIL the nested "
            f"execution; got {bad['status']!r}")
        assert bad["error"] == "States.TaskFailed", (
            f"unexpected error for a parent role lacking kms:Decrypt on the child's key: "
            f"error={bad.get('error')!r} cause={bad.get('cause')!r}")
        # The cause opens with the KMS denial of the parent role's session; what follows carries
        # a per-call request id and attempt count, so the denial sentence is asserted whole.
        cause = _stable_session(bad.get("cause"), bad_role_name) or ""
        assert cause.startswith(denial), (
            f"the nested failure must be the parent role's kms:Decrypt denial on the child's key; "
            f"expected a cause opening {denial!r}, got {bad.get('cause')!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
