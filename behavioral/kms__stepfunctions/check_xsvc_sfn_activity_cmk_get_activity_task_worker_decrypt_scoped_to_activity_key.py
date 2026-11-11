"""xsvc-sfn-activity-cmk-get-activity-task-worker-decrypt-scoped-to-activity-key."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-sfn-activity-cmk-get-activity-task-worker-decrypt-scoped-to-activity-key"
GROUP = "cmk_encryption"
SERVICES = ["kms", "stepfunctions"]
_SESSION_NAME = "sim2real-behav-worker-session"

_REQUEST_ID = re.compile(r"Request ID: [0-9A-Za-z-]+")
_ATTEMPTS = re.compile(r"SDK Attempt Count: [0-9]+")


def _stable(message: str | None) -> str | None:
    if message is None:
        return None
    return _ATTEMPTS.sub("SDK Attempt Count: <n>",
                          _REQUEST_ID.sub("Request ID: <request-id>", message))


@tags("axis:rejection", "dp:api", "plane:data", "cap:c3", "concern:data-plane",
      "concern:negative-classes")
def run(ctx) -> None:
    """GetActivityTask on an activity with its own CMK (run by a state machine with a
    different CMK) authorizes the worker by the activity's key alone: decrypt only on the
    state machine's key is refused just like no grant; decrypt on the activity's key succeeds."""
    sfn = ctx.client("stepfunctions")
    account = ctx.account
    root_principal = f"arn:aws:iam::{account}:root"

    key_sm = _key(ctx, "sm")
    key_act = _key(ctx, "act")

    # The execution role must hold GenerateDataKey/Decrypt on BOTH keys: scheduling a task
    # against a CMK-encrypted activity re-encrypts the task input under the activity's own
    # key, which the state machine's execution role performs, separately from its own key.
    _role_name, role_arn = _exec_role(ctx, [key_sm["Arn"], key_act["Arn"]])

    w_none_name, w_none_arn = _worker_role(ctx, "none")
    w_sm_name, w_sm_arn = _worker_role(ctx, "sm")
    w_act_name, w_act_arn = _worker_role(ctx, "act")

    _grant_key_policy(ctx, key_sm, root_principal, [w_sm_arn])
    _grant_key_policy(ctx, key_act, root_principal, [w_act_arn])

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

    code_none, msg_none = _refused(ctx, w_none_arn, activity_arn)
    assert code_none == "KmsAccessDeniedException", (
        f"a worker with no KMS grant at all must be refused KmsAccessDeniedException; got "
        f"{code_none!r}: {msg_none!r}")
    expected_none = _expected_message(account, w_none_name, key_act["Arn"])
    assert _stable(msg_none) == expected_none, (
        f"expected {expected_none!r}, got {_stable(msg_none)!r}")

    code_sm, msg_sm = _refused(ctx, w_sm_arn, activity_arn)
    assert code_sm == "KmsAccessDeniedException", (
        f"a worker granted decrypt only on the STATE MACHINE's key must still be refused "
        f"KmsAccessDeniedException naming the ACTIVITY's key; got {code_sm!r}: {msg_sm!r}")
    expected_sm = _expected_message(account, w_sm_name, key_act["Arn"])
    assert _stable(msg_sm) == expected_sm, (
        "the state-machine-key grant must make no difference: the refusal must still name "
        f"the activity's key, exactly {expected_sm!r}; got {_stable(msg_sm)!r}")

    resp = _claim(ctx, w_act_arn, activity_arn)
    assert resp.get("taskToken"), (
        "a worker granted decrypt only on the ACTIVITY's key (none on the state machine's "
        f"key) must successfully claim the task; got {resp!r}")
    assert resp["input"] == json.dumps({"marker": marker}), (
        f"GetActivityTask must return the task input byte-for-byte; sent marker {marker!r}, "
        f"got {resp['input']!r}")

    sfn.send_task_success(taskToken=resp["taskToken"], output=json.dumps({"ok": True}))
    desc = _wait_terminal(ctx, exec_arn)
    assert desc["status"] == "SUCCEEDED", (
        f"the execution must SUCCEED once the activity-keyed worker completes the task; got "
        f"{desc['status']!r} error={desc.get('error')!r} cause={desc.get('cause')!r}")


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
        Description=f"sim2real-behav-sfn-activity-cmk-{label} {CHECK[:150]}",
        KeyUsage="ENCRYPT_DECRYPT", Policy=json.dumps(pol),
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK[:250]}],
    )["KeyMetadata"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=meta["KeyId"], PendingWindowInDays=7))
    return meta


def _grant_key_policy(ctx, key: dict, root_principal: str, grantee_arns: list[str]) -> None:
    """Grant decrypt on ``key`` to every ``grantee_arns`` principal, retrying only the
    propagation window during which KMS cannot yet validate a just-created role as a
    principal."""
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


def _worker_role(ctx, label: str) -> tuple[str, str]:
    iam = ctx.client("iam")
    account = ctx.account
    name = ctx.unique_name(f"sim2real-behav-sfn-worker-{label}-")[:64]
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


def _refused(ctx, role_arn: str, activity_arn: str) -> tuple[str, str | None]:
    """Poll GetActivityTask as ``role_arn`` until it is refused KmsAccessDeniedException.

    A fresh role's trust and key-policy grants take a few seconds to propagate, so an
    AccessDeniedException (identity policy not yet effective) may precede the KMS refusal
    this check is about; a call that unexpectedly SUCCEEDS raises, since it would silently
    consume the one scheduled task every other case in this check depends on.
    """
    deadline = time.monotonic() + 60.0
    last = None
    while time.monotonic() < deadline:
        client = _as(ctx, role_arn)
        try:
            resp = client.get_activity_task(activityArn=activity_arn, workerName="sim2real-worker")
        except ClientError as exc:
            err = exc.response["Error"]
            last = (err["Code"], err.get("Message"))
            if last[0] == "KmsAccessDeniedException":
                return last
            if last[0] != "AccessDeniedException":
                return last
            time.sleep(3.0)
            continue
        raise AssertionError(
            f"expected the call to be refused, but it claimed the task: {resp!r}")
    raise AssertionError(f"never saw KmsAccessDeniedException within 60s; last={last!r}")


def _claim(ctx, role_arn: str, activity_arn: str) -> dict:
    """GetActivityTask as the granted worker, retrying the IAM and KMS refusals a fresh role's
    trust and key-policy grant return until they propagate."""
    deadline = time.monotonic() + 60.0
    last = None
    while time.monotonic() < deadline:
        client = _as(ctx, role_arn)
        try:
            return client.get_activity_task(activityArn=activity_arn, workerName="sim2real-worker")
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code not in ("AccessDeniedException", "KmsAccessDeniedException"):
                raise
            last = exc
            time.sleep(3.0)
    raise AssertionError(f"still refused claiming the task after 60s: {last}")


def _expected_message(account: str, role_name: str, key_arn: str) -> str:
    """The exact text KMS returns for a principal with no grant on ``key_arn``.

    The relayed KMS request id and SDK attempt count are the only per-call tokens; both are
    normalized away by ``_stable`` before comparison.
    """
    return (
        f"User: arn:aws:sts::{account}:assumed-role/{role_name}/{_SESSION_NAME} is not "
        f"authorized to perform: kms:Decrypt on resource: {key_arn} because no "
        "identity-based policy allows the kms:Decrypt action (Service: Kms, Status Code: "
        "400, Request ID: <request-id>) (SDK Attempt Count: <n>)"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
