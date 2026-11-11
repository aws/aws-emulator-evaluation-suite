"""lambda-secretsmanager-kms-decrypt-missing-permission-denied."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-secretsmanager-kms-decrypt-missing-permission-denied"
GROUP = "permission-boundary"
SERVICES = ["lambda", "rds", "secretsmanager"]

_HANDLER_SOURCE = """
import boto3
from botocore.exceptions import ClientError


def handler(event, context):
    client = boto3.client("secretsmanager")
    try:
        resp = client.get_secret_value(SecretId=event["secret_id"])
        return {"ok": True, "secret_string": resp["SecretString"]}
    except ClientError as e:
        return {"ok": False, "error_code": e.response["Error"]["Code"]}
"""


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Without kms:Decrypt on a secret's customer managed key the Lambda's GetSecretValue is denied
    and returns no value, while a secret under aws/secretsmanager reads fine; granting
    kms:Decrypt on the key lets the same call return the secret's value."""
    sm = ctx.client("secretsmanager")
    kms = ctx.client("kms")
    iam = ctx.client("iam")

    key = kms.create_key(
        Description="sim2real-behav secretsmanager CMK test key",
        Tags=[{"TagKey": "sim2real:managed", "TagValue": "true"}],
    )
    key_id = key["KeyMetadata"]["KeyId"]
    key_arn = key["KeyMetadata"]["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    cmk_name = ctx.unique_name("sim2real-behav-secret-cmk-")
    cmk_value = "cmk-protected-" + cmk_name
    cmk_secret = sm.create_secret(
        Name=cmk_name,
        SecretString=cmk_value,
        KmsKeyId=key_id,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    cmk_arn = cmk_secret["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=cmk_arn, ForceDeleteWithoutRecovery=True))

    default_name = ctx.unique_name("sim2real-behav-secret-default-")
    default_value = "default-key-" + default_name
    default_secret = sm.create_secret(
        Name=default_name,
        SecretString=default_value,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    default_arn = default_secret["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=default_arn, ForceDeleteWithoutRecovery=True))

    # Broad GetSecretValue grant, deliberately no kms:Decrypt statement anywhere.
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "secretsmanager:GetSecretValue",
                "Resource": "*",
            }
        ],
    }
    role = _create_lambda_role(ctx, policy)
    func = _create_lambda(ctx, role["arn"], _HANDLER_SOURCE)

    cmk_body = _invoke_json(ctx, func["name"], {"secret_id": cmk_arn})
    assert cmk_body.get("ok") is False, cmk_body
    # Missing kms:Decrypt on the CMK surfaces as an access-denied error (the Lambda
    # role's identity policy never granted decrypt on the key), not a data/format
    # failure -- assert on the class of denial rather than pin an exact code string.
    assert "AccessDenied" in cmk_body["error_code"] or cmk_body["error_code"] == "DecryptionFailure", cmk_body
    assert "secret_string" not in cmk_body, f"denied call must not leak plaintext, got {cmk_body}"

    default_body = _invoke_until_ok(ctx, func["name"], {"secret_id": default_arn})
    assert default_body.get("ok") is True, default_body
    assert default_body["secret_string"] == default_value, (
        f"expected secret_string={default_value!r} from the default-key secret, got {default_body}"
    )

    # Restore leg: grant kms:Decrypt on the CMK only, change nothing else, and demand
    # the identical call now succeeds -- this is what proves the earlier denial was
    # caused by the missing grant, not by some other broken dependency.
    restored_policy = {
        "Version": "2012-10-17",
        "Statement": policy["Statement"]
        + [
            {
                "Effect": "Allow",
                "Action": "kms:Decrypt",
                "Resource": key_arn,
            }
        ],
    }
    iam.put_role_policy(
        RoleName=role["name"],
        PolicyName=role["policy_name"],
        PolicyDocument=json.dumps(restored_policy),
    )
    restored_body = _invoke_until_ok(ctx, func["name"], {"secret_id": cmk_arn})
    assert restored_body.get("ok") is True, (
        f"expected ok=True on {cmk_arn} after granting kms:Decrypt on the CMK, got {restored_body}"
    )
    assert restored_body["secret_string"] == cmk_value, (
        f"expected secret_string={cmk_value!r} after restore, got {restored_body}"
    )


_LAMBDA_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)


def _create_lambda_role(ctx, policy_document):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_LAMBDA_TRUST_POLICY,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    role_arn = role["Role"]["Arn"]
    policy_name = f"{role_name}-policy"
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_document)
    )

    def _cleanup():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return {"arn": role_arn, "name": role_name, "policy_name": policy_name}


def _zip_code(source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", source)
    return buf.getvalue()


def _wait_function_active(ctx, name, timeout_s=60.0):
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        state = lam.get_function(FunctionName=name)["Configuration"]["State"]
        if state == "Active":
            return
        time.sleep(2)
    raise AssertionError(f"function {name} never became Active")


def _create_lambda(ctx, role_arn, source, timeout=30):
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-behav-fn-")
    zip_bytes = _zip_code(source)
    deadline = time.monotonic() + 90.0
    resp = None
    while resp is None:
        try:
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=timeout,
                Tags={"sim2real:managed": "true"},
            )
        except ClientError as e:
            code = e.response["Error"]["Code"]
            msg = e.response["Error"].get("Message", "")
            if code == "InvalidParameterValueException" and "cannot be assumed" in msg and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _wait_function_active(ctx, name)
    return {"name": name, "arn": resp["FunctionArn"]}


def _invoke_json(ctx, function_name, payload):
    lam = ctx.client("lambda")
    resp = lam.invoke(
        FunctionName=function_name,
        Payload=json.dumps(payload).encode("utf-8"),
        InvocationType="RequestResponse",
    )
    body_raw = resp["Payload"].read()
    if resp.get("FunctionError"):
        raise AssertionError(f"lambda invocation error: {body_raw!r}")
    return json.loads(body_raw)


def _invoke_until_ok(ctx, function_name, payload, timeout_s=30.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    body = None
    while time.monotonic() < deadline:
        body = _invoke_json(ctx, function_name, payload)
        if body.get("ok"):
            return body
        time.sleep(interval_s)
    return body


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
