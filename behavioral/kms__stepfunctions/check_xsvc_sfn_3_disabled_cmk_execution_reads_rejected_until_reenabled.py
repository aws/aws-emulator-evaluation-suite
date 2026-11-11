"""xsvc-sfn-3-disabled-cmk-execution-reads-rejected-until-reenabled."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-sfn-3-disabled-cmk-execution-reads-rejected-until-reenabled"
GROUP = "cmk_encryption"
SERVICES = ["kms", "stepfunctions"]


# timing:real-time — ttl: 60 s https://docs.aws.amazon.com/step-functions/latest/dg/encryption-at-rest.html
@tags("axis:rejection", "dp:api", "plane:data", "cap:c3", "concern:e2e", "timing:real-time")
def run(ctx) -> None:
    """Disabling a state machine's CMK makes DescribeExecution and GetExecutionHistory raise
    KmsInvalidStateException once the data key reuse period ends; re-enabling it restores
    both reads with the same input, output and events.
    """
    sfn = ctx.client("stepfunctions")
    kms = ctx.client("kms")
    key = _key(ctx)
    _role_name, role_arn = _exec_role(ctx, key["Arn"], ["kms:Decrypt", "kms:GenerateDataKey"])
    sm_arn = _state_machine(ctx, role_arn, key["Arn"])

    _marker, payload = _payload(ctx)
    arn = _start(ctx, sm_arn, payload)
    before = _wait_terminal(ctx, arn)
    assert before["status"] == "SUCCEEDED", (
        f"the execution must SUCCEED before the key is touched; got {before['status']!r}")
    assert before["input"] == payload, f"positive control: input read back {before['input']!r}"
    hist_before = [h["type"] for h in _history(ctx, arn)]

    kms.disable_key(KeyId=key["KeyId"])
    ctx.on_cleanup(lambda: kms.enable_key(KeyId=key["KeyId"]))
    state = kms.describe_key(KeyId=key["KeyId"])["KeyMetadata"]["KeyState"]
    assert state == "Disabled", f"DisableKey must leave the key Disabled; it is {state!r}"

    # A cached data key may legitimately serve reads for up to the reuse period, so poll
    # for the refusal with a deadline of that period plus slack, never a fixed sleep.
    deadline = time.monotonic() + _REUSE_S + 90.0
    reads = {
        "DescribeExecution": lambda: sfn.describe_execution(executionArn=arn),
        "GetExecutionHistory": lambda: sfn.get_execution_history(executionArn=arn),
    }
    refusals: dict[str, tuple[str, str | None]] = {}
    while time.monotonic() < deadline:
        for call, read in reads.items():
            try:
                read()
            except ClientError as exc:
                err = exc.response["Error"]
                refusals[call] = (err["Code"], err.get("Message"))
            else:
                refusals.pop(call, None)
        if len(refusals) == len(reads):
            break
        time.sleep(3.0)
    for call in reads:
        if call not in refusals:
            raise AssertionError(
                f"{call} under a Disabled CMK must be refused within {_REUSE_S}s reuse + 90s, "
                "but it still succeeded")
    describe_code, describe_msg = refusals["DescribeExecution"]
    history_code, history_msg = refusals["GetExecutionHistory"]
    assert describe_code == "KmsInvalidStateException", (
        f"DescribeExecution under a Disabled CMK must raise KmsInvalidStateException within "
        f"{_REUSE_S}s reuse + 90s; got {describe_code!r}")
    expected = _kms_disabled_message(key["Arn"], describe_msg)
    assert describe_msg == expected, (
        f"DescribeExecution must relay KMS's disabled-key message {expected!r}; got {describe_msg!r}")
    assert history_code == "KmsInvalidStateException", (
        f"GetExecutionHistory under a Disabled CMK must raise KmsInvalidStateException; "
        f"got {history_code!r}")
    expected = _kms_disabled_message(key["Arn"], history_msg)
    assert history_msg == expected, (
        f"GetExecutionHistory must relay KMS's disabled-key message {expected!r}; got {history_msg!r}")

    kms.enable_key(KeyId=key["KeyId"])
    deadline = time.monotonic() + _REUSE_S + 120.0
    after = None
    while time.monotonic() < deadline:
        try:
            after = sfn.describe_execution(executionArn=arn)
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "KmsInvalidStateException":
                raise
            time.sleep(3.0)
    assert after is not None, (
        f"DescribeExecution was still KmsInvalidStateException {_REUSE_S + 120}s after "
        "EnableKey — the refusal latched instead of tracking the key state")
    assert after["input"] == payload and after["output"] == before["output"], (
        "after re-enable the execution data must read back unchanged: input "
        f"{after.get('input')!r} output {after.get('output')!r} vs before {before['output']!r}")
    hist_after = [h["type"] for h in _history(ctx, arn)]
    assert hist_after == hist_before, (
        f"after re-enable GetExecutionHistory must return the same events {hist_before}; "
        f"got {hist_after}")


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


def _kms_disabled_message(key_arn: str, actual: str | None) -> str:
    """The exact text Step Functions relays from KMS for a disabled key.

    The relayed KMS request id is the only per-call token. It is taken from the actual message and
    must parse as a UUID; everything else is fixed or built from the key this check created.
    """
    _, _, tail = (actual or "").partition("Request ID: ")
    request_id = tail[:36]
    try:
        uuid.UUID(request_id)
    except ValueError:
        request_id = "<a KMS request id>"
    return (
        f"{key_arn} is disabled. (Service: Kms, Status Code: 400, Request ID: {request_id}) "
        f"(SDK Attempt Count: 1)"
    )


def _payload(ctx) -> tuple[str, str]:
    marker = ctx.unique_name("sim2real-mark-")
    return marker, json.dumps({"marker": marker, "items": [1, "two", {"three": 3.5}],
                               "note": "ünïcode ✓"})


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
