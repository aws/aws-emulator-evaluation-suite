"""send-task-failure-cmk-key-disabled-mid-flight-invalid-state-recovers."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "send-task-failure-cmk-key-disabled-mid-flight-invalid-state-recovers"
GROUP = "cmk_encryption"
SERVICES = ["kms", "stepfunctions"]

# The relayed KMS message ends with the inner KMS call's request id and the SDK attempt count;
# those are the only parts that vary per call.
_REQUEST_ID = re.compile(r"Request ID: [0-9A-Za-z-]+")
_ATTEMPTS = re.compile(r"SDK Attempt Count: [0-9]+")


def _stable(message: str | None) -> str | None:
    if message is None:
        return None
    return _ATTEMPTS.sub("SDK Attempt Count: <n>", _REQUEST_ID.sub("Request ID: <request-id>", message))


# timing:real-time — ttl: 60 s https://docs.aws.amazon.com/step-functions/latest/dg/encryption-at-rest.html
@tags("axis:rejection", "dp:api", "plane:data", "cap:c3", "concern:e2e", "concern:negative-classes",
      "timing:real-time")
def run(ctx) -> None:
    """Disabling a CMK while an activity task is outstanding refuses SendTaskFailure with
    KmsInvalidStateException, and re-enabling the key lets the SAME outstanding token still
    be completed with SendTaskSuccess, so the transient KMS failure never invalidates it.
    """
    sfn = ctx.client("stepfunctions")
    kms = ctx.client("kms")
    key = _key(ctx)
    role_name, role_arn = _exec_role(ctx, key["Arn"])
    act = _activity(ctx)
    definition = json.dumps({
        "StartAt": "T",
        "States": {"T": {"Type": "Task", "Resource": act, "TimeoutSeconds": 1200, "End": True}},
    })
    sm_arn = _state_machine(ctx, role_arn, key["Arn"], definition)

    _marker, payload = _payload(ctx)
    exec_arn = _start(ctx, sm_arn, payload)
    task = _poll_activity_task(ctx, act)

    kms.disable_key(KeyId=key["KeyId"])
    ctx.on_cleanup(lambda: kms.enable_key(KeyId=key["KeyId"]))
    state = kms.describe_key(KeyId=key["KeyId"])["KeyMetadata"]["KeyState"]
    assert state == "Disabled", f"DisableKey must leave the key Disabled; it is {state!r}"
    # fixed-wait: no API reports when Step Functions' cached data key (60 s reuse period) expires
    time.sleep(150)

    code, message = _error(
        lambda: sfn.send_task_failure(taskToken=task["taskToken"], error="Boom", cause="disabled key"))
    assert code == "KmsInvalidStateException", (
        f"SendTaskFailure on an execution whose CMK went Disabled mid-flight must be refused "
        f"KmsInvalidStateException; got {code!r}: {message!r}")
    expected = (
        f"{key['Arn']} is disabled. (Service: Kms, Status Code: 400, "
        "Request ID: <request-id>) (SDK Attempt Count: <n>)"
    )
    assert _stable(message) == expected, f"expected message {expected!r}; got {message!r}"

    kms.enable_key(KeyId=key["KeyId"])
    deadline = time.monotonic() + 240.0
    last = None
    while time.monotonic() < deadline:
        try:
            sfn.send_task_success(taskToken=task["taskToken"], output=json.dumps({"ok": True}))
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "KmsInvalidStateException":
                raise
            last = exc
            time.sleep(5.0)
    else:
        raise AssertionError(
            f"SendTaskSuccess on the SAME outstanding token still KmsInvalidState 240s after "
            f"EnableKey: {last}")

    final = _wait_terminal(ctx, exec_arn)
    assert final["status"] == "SUCCEEDED", (
        f"the token the disabled key refused must still complete once the key recovers; "
        f"got {final['status']!r} error={final.get('error')!r} cause={final.get('cause')!r}")
    assert json.loads(final["output"]) == {"ok": True}, (
        f"SendTaskSuccess output must be relayed exactly; got {final.get('output')!r}")
    assert final["input"] == payload, (
        f"the execution's input must still read back byte-for-byte; got {final.get('input')!r}")


_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
})


def _key(ctx) -> dict:
    kms = ctx.client("kms")
    meta = kms.create_key(
        Description=f"sim2real-behav {CHECK[:180]}",
        KeyUsage="ENCRYPT_DECRYPT",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK[:250]}],
    )["KeyMetadata"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=meta["KeyId"], PendingWindowInDays=7))
    return meta


def _exec_role(ctx, key_arn: str) -> tuple[str, str]:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfnkms3-")[:64]
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=_TRUST, Path="/sim2real/",
        Description="sim2real: sfn CMK execution role",
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


def _activity(ctx) -> str:
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfnkms3-")[:80]
    arn = sfn.create_activity(name=name, tags=[{"key": "sim2real", "value": CHECK[:250]}])["activityArn"]
    ctx.on_cleanup(lambda: sfn.delete_activity(activityArn=arn))
    return arn


def _state_machine(ctx, role_arn: str, key_arn: str, definition: str) -> str:
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfnkms3-")[:80]
    deadline = time.monotonic() + 120.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=definition, roleArn=role_arn, type="STANDARD",
                encryptionConfiguration={
                    "type": "CUSTOMER_MANAGED_KMS_KEY", "kmsKeyId": key_arn,
                    "kmsDataKeyReusePeriodSeconds": 60,
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


def _start(ctx, sm_arn: str, payload: str) -> str:
    """StartExecution, retrying only KmsAccessDeniedException while the execution role's
    trust and KMS grants propagate."""
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
    raise AssertionError(
        f"StartExecution still KmsAccessDenied 150s after the execution role (which holds "
        f"kms:GenerateDataKey and kms:Decrypt) was created: {last}")


def _stop_if_running(sfn, arn: str) -> None:
    if sfn.describe_execution(executionArn=arn)["status"] == "RUNNING":
        sfn.stop_execution(executionArn=arn)


def _wait_terminal(ctx, arn: str) -> dict:
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + 60.0
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=arn)
        if last["status"] != "RUNNING":
            return last
        time.sleep(1.0)
    raise AssertionError(f"execution {arn} still RUNNING after 60s: {last!r}")


def _poll_activity_task(ctx, activity_arn: str, *, timeout_s: float = 65.0) -> dict:
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sfn.get_activity_task(activityArn=activity_arn)
        if resp.get("taskToken"):
            return resp
        time.sleep(0.5)
    raise AssertionError(f"no activity task scheduled within {timeout_s}s")


def _error(fn) -> tuple[str, str | None]:
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _payload(ctx) -> tuple[str, str]:
    marker = ctx.unique_name("sim2real-mark-")
    return marker, json.dumps({"marker": marker})


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
