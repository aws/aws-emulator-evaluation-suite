"""xsvc-sfn-express-cmk-start-sync-execution-caller-decrypt-required-unless-metadata-only."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-sfn-express-cmk-start-sync-execution-caller-decrypt-required-unless-metadata-only"
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
    """StartSyncExecution on a CMK-encrypted EXPRESS machine needs the CALLER's own KMS
    decrypt grant for includedData=ALL_DATA (independent of the execution role's grant);
    the same ungranted caller succeeds under METADATA_ONLY, which omits input/output."""
    account = ctx.account
    root_principal = f"arn:aws:iam::{account}:root"

    key = _key(ctx)
    _role_name, role_arn = _exec_role(ctx, key["Arn"])
    caller_name, caller_arn = _caller_role(ctx)
    sm_arn = _state_machine(ctx, role_arn, key["Arn"])

    marker1 = ctx.unique_name("sim2real-mark-")
    code, message = _refused_all_data(ctx, caller_arn, sm_arn, marker1)
    assert code == "KmsAccessDeniedException", (
        f"a caller with no KMS grant must be refused ALL_DATA with KmsAccessDeniedException; "
        f"got {code!r}: {message!r}")
    expected = _expected_denied_message(account, caller_name, key["Arn"])
    assert _stable(message) == expected, f"expected {expected!r}, got {_stable(message)!r}"

    marker2 = ctx.unique_name("sim2real-mark-")
    resp = _sync(ctx, caller_arn, sm_arn, marker2, "METADATA_ONLY")
    assert resp["status"] == "SUCCEEDED", (
        f"the SAME ungranted caller must succeed under METADATA_ONLY; got {resp['status']!r}")
    for field in ("input", "output", "inputDetails", "outputDetails"):
        assert field not in resp, (
            f"METADATA_ONLY must omit {field!r} entirely since it is KMS-protected data the "
            f"caller cannot decrypt; the response carried it: {resp.get(field)!r}")
    assert "billingDetails" in resp, (
        f"METADATA_ONLY must still carry billingDetails, which is not KMS-protected; got {resp!r}")

    _grant_key_policy(ctx, key, root_principal, [caller_arn])
    marker3 = ctx.unique_name("sim2real-mark-")
    resp_granted = _sync(ctx, caller_arn, sm_arn, marker3, "ALL_DATA")
    assert resp_granted["status"] == "SUCCEEDED", (
        f"once granted decrypt, the caller's ALL_DATA call must succeed; got "
        f"{resp_granted['status']!r}")
    assert resp_granted["input"] == json.dumps({"marker": marker3}), (
        f"ALL_DATA must return the input byte-for-byte; sent marker {marker3!r}, got "
        f"{resp_granted.get('input')!r}")
    assert json.loads(resp_granted["output"]) == {"echo": marker3}, (
        f"ALL_DATA must return the real output; got {resp_granted.get('output')!r}")


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


def _key(ctx) -> dict:
    kms = ctx.client("kms")
    account = ctx.account
    pol = {"Version": "2012-10-17", "Statement": [
        {"Sid": "root", "Effect": "Allow",
         "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
         "Action": "kms:*", "Resource": "*"},
    ]}
    meta = kms.create_key(
        Description=f"sim2real-behav-sfn-express-cmk {CHECK[:150]}",
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
    name = ctx.unique_name("sim2real-behav-sfn-exp-caller-")[:64]
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
            {"Effect": "Allow", "Action": "states:StartSyncExecution", "Resource": "*"}]}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="sfn"))
    return name, arn


def _state_machine(ctx, role_arn: str, key_arn: str) -> str:
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfn-express-cmk-sm-")[:80]
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
    """StartSyncExecution as ``role_arn``, retrying only the identity-policy propagation
    window and, for ALL_DATA, the key-policy grant's; an unexpected refusal past that is a
    defect this check reports, not retries."""
    retry_codes = ("AccessDeniedException",)
    if included_data == "ALL_DATA":
        retry_codes += ("KmsAccessDeniedException",)
    deadline = time.monotonic() + 60.0
    last = None
    while time.monotonic() < deadline:
        client = _as(ctx, role_arn)
        try:
            return client.start_sync_execution(
                stateMachineArn=sm_arn, input=json.dumps({"marker": marker}),
                includedData=included_data)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code not in retry_codes:
                raise
            last = exc
            time.sleep(3.0)
    raise AssertionError(f"StartSyncExecution still refused after 60s: {last}")


def _refused_all_data(ctx, role_arn: str, sm_arn: str, marker: str) -> tuple[str, str | None]:
    deadline = time.monotonic() + 60.0
    last = (None, None)
    while time.monotonic() < deadline:
        client = _as(ctx, role_arn)
        try:
            resp = client.start_sync_execution(
                stateMachineArn=sm_arn, input=json.dumps({"marker": marker}),
                includedData="ALL_DATA")
        except ClientError as exc:
            err = exc.response["Error"]
            last = (err["Code"], err.get("Message"))
            if last[0] == "KmsAccessDeniedException":
                return last
            if last[0] != "AccessDeniedException":
                return last
            time.sleep(3.0)
            continue
        raise AssertionError(f"expected the call to be refused, but it succeeded: {resp!r}")
    raise AssertionError(f"never saw KmsAccessDeniedException within 60s; last={last!r}")


def _expected_denied_message(account: str, role_name: str, key_arn: str) -> str:
    return (
        f"User: arn:aws:sts::{account}:assumed-role/{role_name}/{_SESSION_NAME} is not "
        f"authorized to perform: kms:Decrypt on resource: {key_arn} because no "
        "identity-based policy allows the kms:Decrypt action (Service: Kms, Status Code: "
        "400, Request ID: <request-id>) (SDK Attempt Count: <n>)"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
