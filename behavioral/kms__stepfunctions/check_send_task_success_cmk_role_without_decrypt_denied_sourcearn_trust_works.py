"""send-task-success-cmk-role-without-decrypt-denied-sourcearn-trust-works."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "send-task-success-cmk-role-without-decrypt-denied-sourcearn-trust-works"
GROUP = "cmk_encryption"
SERVICES = ["kms", "stepfunctions"]

# The relayed KMS message ends with the inner KMS call's request id and the SDK attempt count,
# and names the execution role's per-session name Step Functions mints at random; those are the
# only parts that vary per call.
_REQUEST_ID = re.compile(r"Request ID: [0-9A-Za-z-]+")
_ATTEMPTS = re.compile(r"SDK Attempt Count: [0-9]+")


def _stable(message: str | None) -> str | None:
    if message is None:
        return None
    return _ATTEMPTS.sub("SDK Attempt Count: <n>", _REQUEST_ID.sub("Request ID: <request-id>", message))


def _stable_session(message: str | None, role_name: str) -> str | None:
    if message is None:
        return None
    pattern = re.compile(rf"(assumed-role/{re.escape(role_name)}/)[^ ]+")
    return pattern.sub(r"\1<session>", message, count=1)


# timing:real-time — ttl: 60 s https://docs.aws.amazon.com/step-functions/latest/dg/encryption-at-rest.html
@tags("axis:rejection", "dp:api", "plane:data", "cap:c3", "concern:e2e", "concern:negative-classes",
      "timing:real-time")
def run(ctx) -> None:
    """SendTaskSuccess on a CMK execution is refused KmsAccessDeniedException once the
    execution role's kms:Decrypt grant is revoked, and SUCCEEDS on the same outstanding
    token once restored, through a role trusted via aws:SourceArn on a non-ASCII-named machine.
    """
    sfn = ctx.client("stepfunctions")
    iam = ctx.client("iam")
    key = _key(ctx)

    sm_name = _sm_name(ctx)
    sm_arn = f"arn:aws:states:{ctx.region}:{ctx.account}:stateMachine:{sm_name}"
    role_name, role_arn = _exec_role(ctx, sm_arn, key["Arn"])

    act = _activity(ctx)
    definition = json.dumps({
        "StartAt": "T",
        "States": {"T": {"Type": "Task", "Resource": act, "TimeoutSeconds": 1200, "End": True}},
    })
    _create_state_machine(ctx, sm_name, sm_arn, role_arn, key["Arn"], definition)

    trust = iam.get_role(RoleName=role_name)["Role"]["AssumeRolePolicyDocument"]
    condition = trust["Statement"][0]["Condition"]["StringEquals"]
    assert condition["aws:SourceArn"] == sm_arn, (
        f"the role's trust must condition on this exact machine's ARN; got {condition!r}")

    marker, payload = _payload(ctx)
    exec_arn = _start(ctx, sm_arn, payload)
    task = _poll_activity_task(ctx, act)

    _put_role_kms_policy(ctx, role_name, key["Arn"], decrypt=False)
    # IAM has no condition to poll for a revoked grant taking effect; a single determinative
    # call follows a bounded wait, never a retry that could consume the outstanding token on a
    # transient pre-propagation success.
    # fixed-wait: IAM exposes no condition to poll for a revoked grant taking effect
    time.sleep(150)
    code, message = _error(
        lambda: sfn.send_task_success(taskToken=task["taskToken"], output=json.dumps({"ok": True})))
    assert code == "KmsAccessDeniedException", (
        f"SendTaskSuccess must be refused KmsAccessDeniedException once the execution role's "
        f"kms:Decrypt grant is revoked; got {code!r}: {message!r}")
    expected = (
        f"User: arn:aws:sts::{ctx.account}:assumed-role/{role_name}/<session> is not authorized "
        f"to perform: kms:Decrypt on resource: {key['Arn']} because no identity-based policy "
        "allows the kms:Decrypt action (Service: Kms, Status Code: 400, Request ID: <request-id>) "
        "(SDK Attempt Count: <n>)"
    )
    assert _stable_session(_stable(message), role_name) == expected, f"expected message {expected!r}; got {message!r}"

    _put_role_kms_policy(ctx, role_name, key["Arn"], decrypt=True)
    deadline = time.monotonic() + 300.0
    last = None
    while time.monotonic() < deadline:
        try:
            sfn.send_task_success(taskToken=task["taskToken"], output=json.dumps({"ok": True}))
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "KmsAccessDeniedException":
                raise
            last = exc
            time.sleep(4.0)
    else:
        raise AssertionError(f"SendTaskSuccess on the SAME token still KmsAccessDenied 300s "
                             f"after restoring kms:Decrypt: {last}")

    final = _wait_terminal(ctx, exec_arn)
    assert final["status"] == "SUCCEEDED", (
        f"the still-outstanding token must still be usable once Decrypt is restored; "
        f"got {final['status']!r} error={final.get('error')!r} cause={final.get('cause')!r}")
    assert json.loads(final["output"]) == {"ok": True}, (
        f"SendTaskSuccess output must be relayed exactly; got {final.get('output')!r}")
    assert final["input"] == payload, (
        f"the input of this non-ASCII-named machine must still read back byte-for-byte; "
        f"got {final.get('input')!r}, sent {payload!r}, marker {marker!r}")


def _key(ctx) -> dict:
    kms = ctx.client("kms")
    meta = kms.create_key(
        Description=f"sim2real-behav {CHECK[:180]}",
        KeyUsage="ENCRYPT_DECRYPT",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK[:250]}],
    )["KeyMetadata"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=meta["KeyId"], PendingWindowInDays=7))
    return meta


def _sm_name(ctx) -> str:
    """A state machine name this check creates, carrying a non-ASCII character throughout."""
    return (ctx.unique_name("sim2real-behav-sfnkms2-") + "-münchen")[:80]


def _exec_role(ctx, sm_arn: str, key_arn: str) -> tuple[str, str]:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfnkms2-")[:64]
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
            "Action": "sts:AssumeRole",
            "Condition": {"StringEquals": {
                "aws:SourceArn": sm_arn, "aws:SourceAccount": ctx.account}},
        }],
    }
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(trust), Path="/sim2real/",
        Description="sim2real: sfn CMK execution role scoped by aws:SourceArn",
        Tags=[{"Key": "sim2real", "Value": CHECK[:250]}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    _put_role_kms_policy(ctx, name, key_arn, decrypt=True)
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="kms"))
    return name, arn


def _put_role_kms_policy(ctx, role_name: str, key_arn: str, *, decrypt: bool) -> None:
    actions = ["kms:Decrypt", "kms:GenerateDataKey"] if decrypt else ["kms:GenerateDataKey"]
    ctx.client("iam").put_role_policy(
        RoleName=role_name, PolicyName="kms",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": actions, "Resource": key_arn}]}),
    )


def _activity(ctx) -> str:
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfnkms2-")[:80]
    arn = sfn.create_activity(name=name, tags=[{"key": "sim2real", "value": CHECK[:250]}])["activityArn"]
    ctx.on_cleanup(lambda: sfn.delete_activity(activityArn=arn))
    return arn


def _create_state_machine(ctx, name: str, expected_arn: str, role_arn: str, key_arn: str,
                          definition: str) -> None:
    sfn = ctx.client("stepfunctions")
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
        assert arn == expected_arn, (
            f"the non-ASCII name's own ARN must match what the trust condition was built from; "
            f"CreateStateMachine returned {arn!r}, expected {expected_arn!r}")
        ctx.on_cleanup(lambda a=arn: sfn.delete_state_machine(stateMachineArn=a))
        return
    raise AssertionError(f"CreateStateMachine still AccessDenied after 120s: {last}")


def _start(ctx, sm_arn: str, payload: str) -> str:
    """StartExecution, retrying only a KMS or trust refusal while the execution role's trust
    and KMS grants propagate."""
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + 150.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.start_execution(stateMachineArn=sm_arn, input=payload)["executionArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("KmsAccessDeniedException", "AccessDeniedException"):
                raise
            last = exc
            time.sleep(4.0)
            continue
        ctx.on_cleanup(lambda: _stop_if_running(sfn, arn))
        return arn
    raise AssertionError(
        f"StartExecution still denied 150s after the execution role (which holds "
        f"kms:Decrypt, kms:GenerateDataKey and a trust scoped to this machine's ARN) was "
        f"created: {last}")


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
    return marker, json.dumps({"marker": marker, "note": "ünïcode ✓"})


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
