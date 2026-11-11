"""lambda-secretsmanager-describe-secret-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-secretsmanager-describe-secret-positive"
GROUP = "sdk-call"
SERVICES = ["lambda", "rds", "secretsmanager"]

_HANDLER_SOURCE = """
import boto3
from botocore.exceptions import ClientError


def handler(event, context):
    client = boto3.client("secretsmanager")
    try:
        resp = client.describe_secret(SecretId=event["secret_id"])
        return {
            "ok": True,
            "name": resp.get("Name"),
            "arn": resp.get("ARN"),
            "rotation_enabled": resp.get("RotationEnabled", False),
            "tags": resp.get("Tags", []),
        }
    except ClientError as e:
        return {"ok": False, "error_code": e.response["Error"]["Code"]}
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda function calls DescribeSecret and observes the metadata fields
    (Name, ARN, RotationEnabled, Tags) that Secrets Manager returns for the secret."""
    sm = ctx.client("secretsmanager")
    secret_name = ctx.unique_name("sim2real-behav-secret-")
    secret = sm.create_secret(
        Name=secret_name,
        SecretString="describe-me",
        Tags=[{"Key": "sim2real-env", "Value": "behavioral"}],
    )
    secret_arn = secret["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True))

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "secretsmanager:DescribeSecret",
                "Resource": secret_arn,
            }
        ],
    }
    role_arn = _create_lambda_role(ctx, policy)
    func = _create_lambda(ctx, role_arn, _HANDLER_SOURCE)

    body = _invoke_until_ok(ctx, func["name"], {"secret_id": secret_arn})
    assert body.get("ok") is True, f"lambda-side DescribeSecret failed: {body}"
    assert body["name"] == secret_name, f"expected Name={secret_name!r}, got {body['name']!r}"
    assert body["arn"] == secret_arn, f"expected ARN={secret_arn!r}, got {body['arn']!r}"
    assert body["rotation_enabled"] is False, (
        f"expected RotationEnabled=False for a secret with no rotation configured, "
        f"got {body['rotation_enabled']!r}"
    )
    assert {"Key": "sim2real-env", "Value": "behavioral"} in body["tags"], (
        f"expected the created tag in DescribeSecret's Tags, got {body['tags']!r}"
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
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_LAMBDA_TRUST_POLICY)
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
    raise AssertionError(f"lambda invocation never reported ok=True within {timeout_s}s: last body={body}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
