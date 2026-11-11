"""xsvc-sfn-activity-cmk-disabled-denies-get-activity-task-until-reenabled."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-sfn-activity-cmk-disabled-denies-get-activity-task-until-reenabled"
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
_SESSION_NAME = "sim2real-behav-worker-session"


@tags("axis:rejection", "dp:api", "plane:data", "cap:c3", "concern:data-plane",
      "concern:negative-classes")
def run(ctx) -> None:
    """Disabling a CMK-encrypted activity's own key makes GetActivityTask raise
    KmsInvalidStateException for a worker otherwise authorized, independent of the state
    machine's own (different) CMK; re-enabling the key restores delivery of the same task.
    """
    sfn = ctx.client("stepfunctions")
    kms = ctx.client("kms")

    key_sm = _key(ctx, "sm")
    key_act = _key(ctx, "act")
    account = ctx.account
    root_principal = f"arn:aws:iam::{account}:root"

    _role_name, role_arn = _exec_role(ctx, [key_sm["Arn"], key_act["Arn"]])
    worker_name, worker_arn = _worker_role(ctx)
    _grant_key_policy(ctx, key_act, root_principal, [worker_arn])

    act_name = ctx.unique_name("sim2real-behav-cmk-activity-")[:80]
    activity_arn = sfn.create_activity(
        name=act_name,
        encryptionConfiguration={"type": "CUSTOMER_MANAGED_KMS_KEY", "kmsKeyId": key_act["Arn"]},
        tags=[{"key": "sim2real", "value": CHECK[:250]}],
    )["activityArn"]
    ctx.on_cleanup(lambda: sfn.delete_activity(activityArn=activity_arn))

    definition = json.dumps({
        "StartAt": "Work",
        "States": {"Work": {"Type": "Task", "Resource": activity_arn,
                             "TimeoutSeconds": 300, "End": True}},
    })
    sm_arn = _state_machine(ctx, role_arn, key_sm["Arn"], definition)

    marker = ctx.unique_name("sim2real-mark-")
    exec_arn = _start(ctx, sm_arn, json.dumps({"marker": marker}))
    _wait_scheduled(ctx, exec_arn)

    resp = _claim(ctx, worker_arn, activity_arn)
    assert resp.get("taskToken") and resp["input"] == json.dumps({"marker": marker}), (
        f"positive control: an authorized worker must claim the task with its input intact; "
        f"got {resp!r}")
    sfn.send_task_success(taskToken=resp["taskToken"], output=json.dumps({"ok": True}))
    before = _wait_terminal(ctx, exec_arn)
    assert before["status"] == "SUCCEEDED", (
        f"positive control execution must SUCCEED before the key is touched; got "
        f"{before['status']!r}")

    kms.disable_key(KeyId=key_act["KeyId"])
    ctx.on_cleanup(lambda: kms.enable_key(KeyId=key_act["KeyId"]))
    state = kms.describe_key(KeyId=key_act["KeyId"])["KeyMetadata"]["KeyState"]
    assert state == "Disabled", f"DisableKey must leave the activity's key Disabled; got {state!r}"

    marker2 = ctx.unique_name("sim2real-mark-")
    exec_arn2 = _start(ctx, sm_arn, json.dumps({"marker": marker2}))
    _wait_scheduled(ctx, exec_arn2)

    code, message = _wait_invalid_state(ctx, worker_arn, activity_arn)
    assert code == "KmsInvalidStateException", (
        f"GetActivityTask under a Disabled activity CMK must raise KmsInvalidStateException; "
        f"got {code!r}: {message!r}")
    expected = _kms_disabled_message(key_act["Arn"])
    assert _stable(message) == expected, f"expected {expected!r}, got {message!r}"

    kms.enable_key(KeyId=key_act["KeyId"])
    resp2 = _claim(ctx, worker_arn, activity_arn)
    assert resp2.get("taskToken") and resp2["input"] == json.dumps({"marker": marker2}), (
        f"once the activity's key is re-enabled, the SAME still-scheduled task must be "
        f"claimable with its original input intact; got {resp2!r}")
    sfn.send_task_success(taskToken=resp2["taskToken"], output=json.dumps({"ok": True}))
    after = _wait_terminal(ctx, exec_arn2)
    assert after["status"] == "SUCCEEDED", (
        f"the execution must SUCCEED once the re-enabled key lets the task be delivered; got "
        f"{after['status']!r} error={after.get('error')!r} cause={after.get('cause')!r}")


_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
})

_REUSE_S = 60


def _key(ctx, label: str) -> dict:
    kms = ctx.client("kms")
    account = ctx.account
    pol = {"Version": "2012-10-17", "Statement": [
        {"Sid": "root", "Effect": "Allow",
         "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
         "Action": "kms:*", "Resource": "*"},
    ]}
    meta = kms.create_key(
        Description=f"sim2real-behav-sfn-activity-cmk-disable-{label} {CHECK[:130]}",
        KeyUsage="ENCRYPT_DECRYPT", Policy=json.dumps(pol),
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK[:250]}],
    )["KeyMetadata"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=meta["KeyId"], PendingWindowInDays=7))
    return meta


def _grant_key_policy(ctx, key: dict, root_principal: str, grantee_arns: list[str]) -> None:
    kms = ctx.client("kms")
    statements = [{"Sid": "root", "Effect": "Allow", "Principal": {"AWS": root_principal},
                   "Action": "kms:*", "Resource": "*"}]
    for i, arn in enumerate(grantee_arns):
        statements.append({"Sid": f"grant{i}", "Effect": "Allow", "Principal": {"AWS": arn},
                            "Action": ["kms:Decrypt", "kms:DescribeKey"], "Resource": "*"})
    deadline = time.monotonic() + 120.0
    while True:
        try:
            kms.put_key_policy(KeyId=key["KeyId"], PolicyName="default",
                                Policy=json.dumps({"Version": "2012-10-17",
                                                    "Statement": statements}))
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "MalformedPolicyDocumentException" or \
                    time.monotonic() > deadline:
                raise
            time.sleep(3.0)


def _exec_role(ctx, key_arns: list[str]) -> tuple[str, str]:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfn-exec-")[:64]
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=_TRUST, Path="/sim2real/",
        Description="sim2real: sfn activity+sm CMK execution role",
        Tags=[{"Key": "sim2real", "Value": CHECK[:250]}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(
        RoleName=name, PolicyName="kms",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": ["kms:Decrypt", "kms:GenerateDataKey"],
             "Resource": key_arns}]}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="kms"))
    return name, arn


def _worker_role(ctx) -> tuple[str, str]:
    iam = ctx.client("iam")
    account = ctx.account
    name = ctx.unique_name("sim2real-behav-sfn-worker-")[:64]
    trust = json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
         "Action": "sts:AssumeRole"}]})
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=trust, Path="/sim2real/",
        Description="sim2real: sfn activity worker",
        Tags=[{"Key": "sim2real", "Value": CHECK[:250]}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(
        RoleName=name, PolicyName="sfn",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "states:GetActivityTask", "Resource": "*"}]}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="sfn"))
    return name, arn


def _state_machine(ctx, role_arn: str, key_sm_arn: str, definition: str) -> str:
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfn-activity-cmk-sm-")[:80]
    deadline = time.monotonic() + 120.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=definition, roleArn=role_arn, type="STANDARD",
                encryptionConfiguration={
                    "type": "CUSTOMER_MANAGED_KMS_KEY", "kmsKeyId": key_sm_arn,
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
    raise AssertionError(f"CreateStateMachine still denied after 120s: {last}")


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


def _wait_scheduled(ctx, exec_arn: str) -> None:
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + 60.0
    events: list[str] = []
    while time.monotonic() < deadline:
        events = [h["type"] for h in sfn.get_execution_history(executionArn=exec_arn)["events"]]
        if "ActivityScheduled" in events:
            return
        time.sleep(2.0)
    raise AssertionError(f"ActivityScheduled did not appear within 60s; saw {events}")


def _wait_terminal(ctx, exec_arn: str) -> dict:
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + 60.0
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] != "RUNNING":
            return last
        time.sleep(2.0)
    raise AssertionError(f"execution still RUNNING after 60s: {last!r}")


def _assume(ctx, role_arn: str) -> dict:
    sts = ctx.client("sts")
    deadline = time.monotonic() + 60.0
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return sts.assume_role(RoleArn=role_arn, RoleSessionName=_SESSION_NAME)["Credentials"]
        except ClientError as exc:
            last_exc = exc
            time.sleep(3.0)
    raise AssertionError(f"could not assume role {role_arn!r}: {last_exc}")


def _as(ctx, role_arn: str):
    creds = _assume(ctx, role_arn)
    return ctx.client("stepfunctions", creds={
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretAccessKey"],
        "aws_session_token": creds["SessionToken"],
    })


def _claim(ctx, role_arn: str, activity_arn: str) -> dict:
    deadline = time.monotonic() + 60.0
    last = None
    while time.monotonic() < deadline:
        client = _as(ctx, role_arn)
        try:
            return client.get_activity_task(activityArn=activity_arn, workerName="sim2real-worker")
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code != "AccessDeniedException":
                raise
            last = exc
            time.sleep(3.0)
    raise AssertionError(f"still AccessDenied claiming the task after 60s: {last}")


def _wait_invalid_state(ctx, role_arn: str, activity_arn: str) -> tuple[str, str | None]:
    """Poll GetActivityTask until it raises KmsInvalidStateException.

    A cached data key may legitimately still serve for up to the reuse period, so this polls
    rather than asserting on the first call.
    """
    deadline = time.monotonic() + _REUSE_S + 90.0
    last = (None, None)
    while time.monotonic() < deadline:
        client = _as(ctx, role_arn)
        try:
            resp = client.get_activity_task(activityArn=activity_arn, workerName="sim2real-worker")
        except ClientError as exc:
            err = exc.response["Error"]
            last = (err["Code"], err.get("Message"))
            if last[0] == "KmsInvalidStateException":
                return last
            if last[0] not in ("AccessDeniedException",):
                return last
        else:
            if resp.get("taskToken"):
                raise AssertionError(
                    f"expected the disabled key to refuse delivery, but the task was "
                    f"claimed: {resp!r}")
        time.sleep(3.0)
    raise AssertionError(f"never saw KmsInvalidStateException within budget; last={last!r}")


def _kms_disabled_message(key_arn: str) -> str:
    """The exact text Step Functions relays from KMS for a disabled key, request id and attempt
    count masked."""
    return (
        f"{key_arn} is disabled. (Service: Kms, Status Code: 400, Request ID: <request-id>) "
        "(SDK Attempt Count: <n>)"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
