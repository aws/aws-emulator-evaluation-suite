"""xsvc-sfn-3-cmk-encrypted-execution-data-reads-back-exactly."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-sfn-3-cmk-encrypted-execution-data-reads-back-exactly"
GROUP = "cmk_encryption"
SERVICES = ["kms", "stepfunctions"]


@tags("axis:happy-path", "dp:api", "plane:data", "cap:c3", "concern:e2e")
def run(ctx) -> None:
    """A CMK-encrypted state machine runs to SUCCEEDED, and DescribeExecution and
    GetExecutionHistory return its input byte-for-byte and its derived output exactly.
    """
    sfn = ctx.client("stepfunctions")
    key = _key(ctx)
    _role_name, role_arn = _exec_role(ctx, key["Arn"], ["kms:Decrypt", "kms:GenerateDataKey"])
    sm_arn = _state_machine(ctx, role_arn, key["Arn"])

    enc = sfn.describe_state_machine(stateMachineArn=sm_arn).get("encryptionConfiguration")
    assert enc == {"type": "CUSTOMER_MANAGED_KMS_KEY", "kmsKeyId": key["Arn"],
                   "kmsDataKeyReusePeriodSeconds": _REUSE_S}, (
        f"DescribeStateMachine must report the CMK configuration it was created with; got {enc!r}")

    marker, payload = _payload(ctx)
    arn = _start(ctx, sm_arn, payload)
    desc = _wait_terminal(ctx, arn)
    assert desc["status"] == "SUCCEEDED", (
        f"a CMK-encrypted Pass-only execution must SUCCEED; got {desc['status']!r} "
        f"error={desc.get('error')!r} cause={desc.get('cause')!r}")
    assert desc["input"] == payload, (
        f"DescribeExecution must return the input byte-for-byte: sent {payload!r}, "
        f"got {desc.get('input')!r}")
    want_out = {"echo": marker, "items": [1, "two", {"three": 3.5}], "fixed": 7}
    assert json.loads(desc["output"]) == want_out, (
        f"DescribeExecution output must be the Pass state's reshaping of the input "
        f"{want_out!r}; got {desc.get('output')!r}")

    hist = _history(ctx, arn)
    types = [h["type"] for h in hist]
    assert types[0] == "ExecutionStarted" and types[-1] == "ExecutionSucceeded", (
        f"history must run ExecutionStarted .. ExecutionSucceeded; got {types}")
    assert hist[0]["executionStartedEventDetails"]["input"] == payload, (
        "GetExecutionHistory's ExecutionStarted input must equal what was sent; got "
        f"{hist[0]['executionStartedEventDetails'].get('input')!r}")
    assert hist[-1]["executionSucceededEventDetails"]["output"] == desc["output"], (
        "GetExecutionHistory's ExecutionSucceeded output must equal DescribeExecution's: "
        f"{hist[-1]['executionSucceededEventDetails'].get('output')!r} vs {desc['output']!r}")


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



def _payload(ctx) -> tuple[str, str]:
    marker = ctx.unique_name("sim2real-mark-")
    return marker, json.dumps({"marker": marker, "items": [1, "two", {"three": 3.5}],
                               "note": "ünïcode ✓"})


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
