"""lambda-secretsmanager-get-secret-value-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-secretsmanager-get-secret-value-positive"
GROUP = "sdk-call"
SERVICES = ["lambda", "rds", "secretsmanager"]

_HANDLER_SOURCE = """
import boto3
from botocore.exceptions import ClientError


def handler(event, context):
    client = boto3.client("secretsmanager")
    try:
        resp = client.get_secret_value(SecretId=event["secret_id"])
        return {
            "ok": True,
            "secret_string": resp["SecretString"],
            "version_id": resp["VersionId"],
        }
    except ClientError as e:
        return {"ok": False, "error_code": e.response["Error"]["Code"]}
"""


@tags("axis:happy-path", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda function whose execution role grants GetSecretValue on a secret's ARN
    retrieves the secret's plaintext value via boto3 inside the handler."""
    sm = ctx.client("secretsmanager")
    secret_name = ctx.unique_name("sim2real-behav-secret-")
    secret_value = "s3cr3t-" + secret_name
    secret = sm.create_secret(
        Name=secret_name,
        SecretString=secret_value,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    secret_arn = secret["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True))

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "secretsmanager:GetSecretValue",
                "Resource": secret_arn,
            }
        ],
    }
    role_arn = _create_lambda_role(ctx, policy)
    func = _create_lambda(ctx, role_arn, _HANDLER_SOURCE)

    body = _invoke_until_ok(ctx, func["name"], {"secret_id": secret_arn})
    assert body.get("ok") is True, body
    assert body["secret_string"] == secret_value

    versions = sm.list_secret_version_ids(SecretId=secret_arn)["Versions"]
    current = [v for v in versions if "AWSCURRENT" in v.get("VersionStages", [])]
    assert len(current) == 1, versions
    assert body["version_id"] == current[0]["VersionId"], (body["version_id"], current)


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
        Tags=[{"Key": "sim2real", "Value": "true"}],
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
    return role_arn


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
                Tags={"sim2real": "true"},
            )
        except ClientError as e:
            code = e.response["Error"]["Code"]
            msg = e.response["Error"].get("Message", "")
            # IAM role trust propagation is documented as eventually consistent
            # (can take up to ~10s); retry create_function until it lands.
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
    # IAM identity-policy grants are also eventually consistent; retry the
    # invocation until the permission has propagated rather than sleeping blindly.
    deadline = time.monotonic() + timeout_s
    body = None
    while time.monotonic() < deadline:
        body = _invoke_json(ctx, function_name, payload)
        if body.get("ok"):
            return body
        time.sleep(interval_s)
    raise AssertionError(f"invocation never returned ok=True within {timeout_s}s, last body={body}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
