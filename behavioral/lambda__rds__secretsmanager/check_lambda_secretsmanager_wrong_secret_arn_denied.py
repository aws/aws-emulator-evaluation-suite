"""lambda-secretsmanager-wrong-secret-arn-denied."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-secretsmanager-wrong-secret-arn-denied"
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
    """A role whose GetSecretValue grant names one secret ARN gets AccessDeniedException and no
    value for a different secret, while the same function reads the secret it is scoped to."""
    sm = ctx.client("secretsmanager")

    allowed_name = ctx.unique_name("sim2real-behav-secret-allowed-")
    allowed_value = "allowed-" + allowed_name
    allowed_secret = sm.create_secret(
        Name=allowed_name, SecretString=allowed_value, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    allowed_arn = allowed_secret["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=allowed_arn, ForceDeleteWithoutRecovery=True))

    other_name = ctx.unique_name("sim2real-behav-secret-other-")
    other_value = "other-" + other_name
    other_secret = sm.create_secret(
        Name=other_name, SecretString=other_value, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    other_arn = other_secret["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=other_arn, ForceDeleteWithoutRecovery=True))

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "secretsmanager:GetSecretValue",
                "Resource": allowed_arn,
            }
        ],
    }
    role_arn = _create_lambda_role(ctx, policy)
    func = _create_lambda(ctx, role_arn, _HANDLER_SOURCE)

    other_body = _invoke_json(ctx, func["name"], {"secret_id": other_arn})
    assert other_body.get("ok") is False, other_body
    assert other_body["error_code"] == "AccessDeniedException", (
        f"expected AccessDeniedException for a secret outside the policy's Resource scope, "
        f"got {other_body}"
    )
    assert "secret_string" not in other_body, (
        f"secret value leaked despite the resource-scoping denial: {other_body}"
    )

    allowed_body = _invoke_until_ok(ctx, func["name"], {"secret_id": allowed_arn})
    assert allowed_body.get("ok") is True, allowed_body
    assert allowed_body["secret_string"] == allowed_value, (
        f"expected the in-scope secret value {allowed_value!r}, got {allowed_body}"
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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
                Tags={"sim2real": CHECK},
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
