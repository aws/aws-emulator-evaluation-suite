"""xsvc-sfn-3-execution-role-without-kms-generate-data-key-start-execution-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-sfn-3-execution-role-without-kms-generate-data-key-start-execution-denied"
GROUP = "cmk_encryption"
SERVICES = ["kms", "stepfunctions"]


@tags("axis:rejection", "dp:api", "plane:data", "cap:c3", "concern:e2e")
def run(ctx) -> None:
    """StartExecution on a CMK-encrypted machine whose execution role lacks kms:GenerateDataKey
    is refused with KmsAccessDeniedException and creates no execution; swapping in a role
    that holds it makes the same machine start and succeed.
    """
    sfn = ctx.client("stepfunctions")
    key = _key(ctx)
    _good_name, good_arn = _exec_role(ctx, key["Arn"], ["kms:Decrypt", "kms:GenerateDataKey"])
    _bad_name, bad_arn = _exec_role(ctx, key["Arn"], ["kms:Decrypt"])
    good_sm = _state_machine(ctx, good_arn, key["Arn"])
    bad_sm = _state_machine(ctx, bad_arn, key["Arn"])
    _marker, payload = _payload(ctx)

    # A twin role of the same age with the grant must keep working, so the denial is the
    # missing action rather than IAM propagation. The execution role, not the caller, is checked.
    first = _start(ctx, good_sm, payload)
    codes = []
    for _ in range(3):
        codes.append(_error_code(lambda: sfn.start_execution(stateMachineArn=bad_sm,
                                                             input=payload),
                                 "StartExecution of the machine whose role lacks "
                                 "kms:GenerateDataKey"))
        _wait_terminal(ctx, _start(ctx, good_sm, payload))
    good_status = _wait_terminal(ctx, first)["status"]
    assert good_status == "SUCCEEDED", (
        f"control: the twin machine whose role holds kms:GenerateDataKey must SUCCEED; got "
        f"{good_status!r}")
    # message varies: it embeds the role session name Step Functions picks at random and the
    # per-request id of the KMS call it made, neither of which the check can know.
    assert codes == ["KmsAccessDeniedException"] * 3, (
        "StartExecution whose execution role lacks kms:GenerateDataKey must be refused with "
        f"KmsAccessDeniedException on every attempt while the twin succeeds; got {codes}")
    listed = sfn.list_executions(stateMachineArn=bad_sm)["executions"]
    assert listed == [], (
        f"a refused StartExecution must create no execution; ListExecutions shows "
        f"{[(e['name'], e['status']) for e in listed]}")

    # Swap in the proven twin role: rewriting the bad role's inline policy instead converges
    # with unbounded latency.
    sfn.update_state_machine(stateMachineArn=bad_sm, roleArn=good_arn)
    role_now = sfn.describe_state_machine(stateMachineArn=bad_sm)["roleArn"]
    assert role_now == good_arn, f"UpdateStateMachine must swap the role; it is {role_now!r}"
    arn = _start(ctx, bad_sm, payload)
    desc = _wait_terminal(ctx, arn)
    assert desc["status"] == "SUCCEEDED" and desc["input"] == payload, (
        f"once its role holds kms:GenerateDataKey the same machine must start and SUCCEED "
        f"with its input intact; got {desc['status']!r} input={desc.get('input')!r}")
    listed = [e["executionArn"] for e in sfn.list_executions(stateMachineArn=bad_sm)["executions"]]
    assert listed == [arn], (
        f"exactly the one repaired execution must exist on the machine; got {listed}")


_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
})

# Pass state that reshapes the input, so the output is execution data derived from it.
_DEFINITION = json.dumps({
    "StartAt": "Shape",
    "States": {
        "Shape": {
            "Type": "Pass",
            "Parameters": {"echo.$": "$.marker", "items.$": "$.items", "fixed": 7},
            "End": True,
        },
    },
})

# StartExecution on a CMK-encrypted machine calls KMS as the execution role; until the role's
# trust propagates (~35s after CreateRole) it fails KmsAccessDeniedException, and IAM exposes
# no condition to poll.
_ROLE_PROPAGATION_S = 150.0


def _key(ctx) -> dict:
    kms = ctx.client("kms")
    meta = kms.create_key(
        Description=f"sim2real-xsvc-sfn3 {CHECK[:200]}",
        KeyUsage="ENCRYPT_DECRYPT",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK[:250]}],
    )["KeyMetadata"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=meta["KeyId"], PendingWindowInDays=7))
    return meta


def _exec_role(ctx, key_arn: str, kms_actions: list[str]) -> tuple[str, str]:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-xsvc-sfn3-kms-")[:64]
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=_TRUST, Path="/sim2real/",
        Description="sim2real-xsvc: sfn CMK execution role",
        Tags=[{"Key": "sim2real", "Value": CHECK[:250]}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    _put_kms_policy(ctx, name, key_arn, kms_actions)
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="kms"))
    return name, arn


def _put_kms_policy(ctx, role_name: str, key_arn: str, kms_actions: list[str]) -> None:
    ctx.client("iam").put_role_policy(
        RoleName=role_name, PolicyName="kms",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": kms_actions, "Resource": key_arn}]}),
    )


def _state_machine(ctx, role_arn: str, key_arn: str) -> str:
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-xsvc-sfn3-kms-")[:80]
    deadline = time.monotonic() + 120.0
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
            time.sleep(5.0)
            continue
        ctx.on_cleanup(lambda a=arn: sfn.delete_state_machine(stateMachineArn=a))
        return arn
    raise AssertionError(f"CreateStateMachine still AccessDenied after 120s: {last}")


# The minimum reuse period: how long Step Functions may serve a cached data key.
_REUSE_S = 60


def _start(ctx, sm_arn: str, payload: str) -> str:
    """StartExecution, retrying only KmsAccessDeniedException while the execution role's
    trust propagates (see _ROLE_PROPAGATION_S)."""
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + _ROLE_PROPAGATION_S
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
    raise AssertionError(
        f"StartExecution still KmsAccessDenied {_ROLE_PROPAGATION_S}s after the execution "
        f"role (which holds kms:GenerateDataKey and kms:Decrypt) was created: {last}")


def _stop_if_running(sfn, arn: str) -> None:
    if sfn.describe_execution(executionArn=arn)["status"] == "RUNNING":
        sfn.stop_execution(executionArn=arn)


def _wait_terminal(ctx, arn: str) -> dict:
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + 120.0
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=arn)
        if last["status"] != "RUNNING":
            return last
        time.sleep(1.0)
    raise AssertionError(f"execution {arn} still RUNNING after 120s (a single Pass): {last!r}")


def _history(ctx, arn: str) -> list[dict]:
    sfn = ctx.client("stepfunctions")
    out, kwargs = [], {"executionArn": arn, "maxResults": 1000}
    while True:
        resp = sfn.get_execution_history(**kwargs)
        out.extend(resp["events"])
        if not resp.get("nextToken"):
            return out
        kwargs["nextToken"] = resp["nextToken"]


def _error_code(fn, call: str) -> str:
    """The error code of the refused call; AssertionError naming the call if it succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    raise AssertionError(f"{call} must be refused, but it succeeded")


def _payload(ctx) -> tuple[str, str]:
    marker = ctx.unique_name("sim2real-mark-")
    return marker, json.dumps({"marker": marker, "items": [1, "two", {"three": 3.5}],
                               "note": "ünïcode ✓"})


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
