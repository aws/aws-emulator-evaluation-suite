"""xsvc-sfn-express-cmk-start-sync-execution-key-policy-deny-and-disabled-key."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-sfn-express-cmk-start-sync-execution-key-policy-deny-and-disabled-key"
GROUP = "cmk_encryption"
SERVICES = ["kms", "stepfunctions"]
_SESSION_NAME = "sim2real-behav-caller-session"

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
    """StartSyncExecution on a CMK-encrypted EXPRESS machine: an explicit key-policy Deny
    on the caller's decrypt grant is KmsAccessDeniedException with distinct wording from a
    plain missing grant; disabling the key instead is KmsInvalidStateException; both recover."""
    account = ctx.account
    root_principal = f"arn:aws:iam::{account}:root"

    key = _key(ctx)
    _role_name, role_arn = _exec_role(ctx, key["Arn"])
    caller_name, caller_arn = _caller_role(ctx)
    sm_arn = _state_machine(ctx, role_arn, key["Arn"])

    allow_statements = [
        {"Sid": "root", "Effect": "Allow", "Principal": {"AWS": root_principal},
         "Action": "kms:*", "Resource": "*"},
        {"Sid": "allowcaller", "Effect": "Allow", "Principal": {"AWS": caller_arn},
         "Action": ["kms:Decrypt", "kms:DescribeKey"], "Resource": "*"},
    ]
    _put_key_policy(ctx, key, allow_statements)

    marker1 = ctx.unique_name("sim2real-mark-")
    pc = _sync(ctx, caller_arn, sm_arn, marker1, "ALL_DATA")
    assert pc["status"] == "SUCCEEDED" and pc["input"] == json.dumps({"marker": marker1}), (
        f"positive control: the granted caller must succeed with its input intact; got {pc!r}")

    deny_statements = allow_statements + [
        {"Sid": "denycaller", "Effect": "Deny", "Principal": {"AWS": caller_arn},
         "Action": "kms:Decrypt", "Resource": "*"},
    ]
    _put_key_policy(ctx, key, deny_statements)
    ctx.on_cleanup(lambda: _put_key_policy(ctx, key, allow_statements))

    code, message = _until_refused(ctx, caller_arn, sm_arn, "KmsAccessDeniedException",
                                   timeout_s=_DENY_PROPAGATION_S)
    assert code == "KmsAccessDeniedException", (
        f"an explicit key-policy Deny must be refused KmsAccessDeniedException; got "
        f"{code!r}: {message!r}")
    expected_deny = _expected_explicit_deny_message(account, caller_name, key["Arn"])
    assert _stable(message) == expected_deny, (
        f"expected {expected_deny!r}, got {_stable(message)!r}")

    _put_key_policy(ctx, key, allow_statements)
    marker3 = ctx.unique_name("sim2real-mark-")
    restored = _until_succeeds(ctx, caller_arn, sm_arn, marker3, ("KmsAccessDeniedException",),
                               timeout_s=_DENY_PROPAGATION_S)
    assert restored["status"] == "SUCCEEDED", (
        f"removing the explicit deny must restore the caller's access; got "
        f"{restored['status']!r}")

    kms = ctx.client("kms")
    kms.disable_key(KeyId=key["KeyId"])
    ctx.on_cleanup(lambda: kms.enable_key(KeyId=key["KeyId"]))
    state = kms.describe_key(KeyId=key["KeyId"])["KeyMetadata"]["KeyState"]
    assert state == "Disabled", f"DisableKey must leave the key Disabled; got {state!r}"

    # A KMS host may still answer with the lifted explicit deny after another host has
    # already honoured the restored policy, so that refusal is retried here too.
    code2, message2 = _until_refused(ctx, caller_arn, sm_arn, "KmsInvalidStateException",
                                     timeout_s=_REUSE_S + 90.0,
                                     lingering=("KmsAccessDeniedException",))
    assert code2 == "KmsInvalidStateException", (
        f"a Disabled CMK must raise KmsInvalidStateException, not KmsAccessDeniedException; "
        f"got {code2!r}: {message2!r}")
    expected_disabled = _kms_disabled_message(key["Arn"])
    assert _stable(message2) == expected_disabled, f"expected {expected_disabled!r}, got {message2!r}"

    kms.enable_key(KeyId=key["KeyId"])
    marker5 = ctx.unique_name("sim2real-mark-")
    final = _until_succeeds(ctx, caller_arn, sm_arn, marker5,
                            ("KmsInvalidStateException", "KmsAccessDeniedException"),
                            timeout_s=_DENY_PROPAGATION_S)
    assert final["status"] == "SUCCEEDED" and final["input"] == json.dumps({"marker": marker5}), (
        f"re-enabling the key must restore StartSyncExecution; got {final!r}")


_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
})

_DEFINITION = json.dumps({
    "StartAt": "Shape",
    "States": {"Shape": {"Type": "Pass", "Parameters": {"echo.$": "$.marker"}, "End": True}},
})

_REUSE_S = 60
# A key-policy change reaches Step Functions' KMS calls eventually, not at once, and not on
# every KMS host together: one call may see the new policy while a later one still sees the old.
_DENY_PROPAGATION_S = 180.0


def _key(ctx) -> dict:
    kms = ctx.client("kms")
    account = ctx.account
    pol = {"Version": "2012-10-17", "Statement": [
        {"Sid": "root", "Effect": "Allow",
         "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
         "Action": "kms:*", "Resource": "*"},
    ]}
    meta = kms.create_key(
        Description=f"sim2real-behav-sfn-express-cmk-deny {CHECK[:130]}",
        KeyUsage="ENCRYPT_DECRYPT", Policy=json.dumps(pol),
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK[:250]}],
    )["KeyMetadata"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=meta["KeyId"], PendingWindowInDays=7))
    return meta


def _put_key_policy(ctx, key: dict, statements: list[dict]) -> None:
    kms = ctx.client("kms")
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


def _exec_role(ctx, key_arn: str) -> tuple[str, str]:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfn-exp-exec-")[:64]
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=_TRUST, Path="/sim2real/",
        Description="sim2real: sfn express CMK execution role",
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


def _caller_role(ctx) -> tuple[str, str]:
    iam = ctx.client("iam")
    account = ctx.account
    name = ctx.unique_name("sim2real-behav-sfn-exp-dcaller-")[:64]
    trust = json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
         "Action": "sts:AssumeRole"}]})
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=trust, Path="/sim2real/",
        Description="sim2real: sfn StartSyncExecution caller",
        Tags=[{"Key": "sim2real", "Value": CHECK[:250]}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(
        RoleName=name, PolicyName="sfn",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "states:StartSyncExecution", "Resource": "*"},
            {"Effect": "Allow", "Action": "kms:Decrypt", "Resource": "*"}]}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="sfn"))
    return name, arn


def _state_machine(ctx, role_arn: str, key_arn: str) -> str:
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfn-express-cmk-deny-sm-")[:80]
    deadline = time.monotonic() + 150.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=_DEFINITION, roleArn=role_arn, type="EXPRESS",
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


def _sync(ctx, role_arn: str, sm_arn: str, marker: str, included_data: str) -> dict:
    """StartSyncExecution as the caller, retried while the caller's IAM grant
    (AccessDeniedException) or the key policy's Allow (KmsAccessDeniedException) propagates."""
    deadline = time.monotonic() + _DENY_PROPAGATION_S
    last = None
    while time.monotonic() < deadline:
        client = _as(ctx, role_arn)
        try:
            return client.start_sync_execution(
                stateMachineArn=sm_arn, input=json.dumps({"marker": marker}),
                includedData=included_data)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code not in ("AccessDeniedException", "KmsAccessDeniedException"):
                raise
            last = exc
            time.sleep(3.0)
    raise AssertionError(
        f"StartSyncExecution still refused after {_DENY_PROPAGATION_S}s while the IAM grant and "
        f"key policy propagate: {last}")


def _until_refused(ctx, role_arn: str, sm_arn: str, expected_code: str, *,
                   timeout_s: float, lingering: tuple[str, ...] = ()) -> tuple[str, str | None]:
    """Start fresh synchronous executions until one is refused with an error other than the
    caller's own IAM propagation or an earlier key change still propagating (lingering);
    return that error's code and message.

    Until the key change propagates (or the cached data key's reuse period lapses), a start
    may still SUCCEED; a sync Express execution leaves nothing behind, so it is retried.
    """
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        client = _as(ctx, role_arn)
        try:
            last = client.start_sync_execution(
                stateMachineArn=sm_arn,
                input=json.dumps({"marker": ctx.unique_name("sim2real-mark-")}),
                includedData="ALL_DATA")
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] != "AccessDeniedException" and err["Code"] not in lingering:
                return err["Code"], err.get("Message")
            last = (err["Code"], err.get("Message"))
        else:
            assert last.get("status") == "SUCCEEDED", (
                f"until {expected_code} takes effect a start must either still SUCCEED or be "
                f"refused; it returned {last!r}")
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"StartSyncExecution was never refused with {expected_code} within "
                f"{timeout_s:.0f}s; last={last!r}")
        time.sleep(3.0)


def _until_succeeds(ctx, role_arn: str, sm_arn: str, marker: str, lingering: tuple[str, ...], *,
                    timeout_s: float) -> dict:
    """StartSyncExecution, retried while the caller's IAM grant or a lifted key refusal
    (lingering) is still propagating."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while True:
        client = _as(ctx, role_arn)
        try:
            return client.start_sync_execution(
                stateMachineArn=sm_arn, input=json.dumps({"marker": marker}),
                includedData="ALL_DATA")
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("AccessDeniedException", *lingering):
                raise
            last_exc = exc
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"StartSyncExecution still refused {timeout_s:.0f}s after the key was "
                f"restored: {last_exc}")
        time.sleep(3.0)


def _expected_explicit_deny_message(account: str, role_name: str, key_arn: str) -> str:
    return (
        f"User: arn:aws:sts::{account}:assumed-role/{role_name}/{_SESSION_NAME} is not "
        f"authorized to perform: kms:Decrypt on resource: {key_arn} with an explicit deny "
        "in a resource-based policy (Service: Kms, Status Code: 400, Request ID: "
        "<request-id>) (SDK Attempt Count: <n>)"
    )


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
