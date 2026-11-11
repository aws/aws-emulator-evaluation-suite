"""lambda-secretsmanager-cross-account-resource-policy-allow."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-secretsmanager-cross-account-resource-policy-allow"
GROUP = "permission-boundary"
SERVICES = ["dynamodb", "lambda", "s3", "secretsmanager"]

_TAGS_KV = [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}]
_TAGS_MAP = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}

# Cross-account sharing relies on the secret's resource policy alone; one account isolates that:
# the role has no identity-based secretsmanager grant, so only the resource policy can allow it.
_HANDLER_CODE = """
import boto3, json
from botocore.exceptions import ClientError

def handler(event, context):
    client = boto3.client("secretsmanager")
    try:
        resp = client.get_secret_value(SecretId=event["secret_id"])
        return {"ok": True, "secret_string": resp.get("SecretString")}
    except ClientError as e:
        return {"ok": False, "error_code": e.response["Error"]["Code"]}
"""


@tags("axis:happy-path", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """A secret resource policy naming a Lambda role lets it read the secret with no identity-based
    grant; a sibling secret without that policy returns AccessDeniedException to the same role."""
    role_arn = _create_role(ctx, [])  # no identity-based secretsmanager permission at all

    granted_value = "granted-via-resource-policy-" + ctx.unique_name("")
    granted_arn = _create_secret(ctx, granted_value)
    sm = ctx.client("secretsmanager")
    allow_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": role_arn},
                "Action": "secretsmanager:GetSecretValue",
                "Resource": "*",
            }
        ],
    }
    _put_resource_policy_with_retry(sm, granted_arn, allow_policy)

    baseline_value = "baseline-no-grant-" + ctx.unique_name("")
    baseline_arn = _create_secret(ctx, baseline_value)

    fn = _create_function(ctx, role_arn, _HANDLER_CODE)

    _, body_granted = _invoke(ctx, fn, {"secret_id": granted_arn})
    assert body_granted["ok"] is True, f"expected ok=True for resource-policy-granted secret, got {body_granted}"
    assert body_granted["secret_string"] == granted_value, (
        f"expected secret_string={granted_value!r}, got {body_granted.get('secret_string')!r}"
    )

    _, body_baseline = _invoke(ctx, fn, {"secret_id": baseline_arn})
    assert body_baseline["ok"] is False, f"expected ok=False for ungranted secret, got {body_baseline}"
    assert body_baseline["error_code"] == "AccessDeniedException", (
        f"expected error_code=AccessDeniedException, got {body_baseline.get('error_code')!r}"
    )
    assert "secret_string" not in body_baseline, f"secret leaked despite denial: {body_baseline}"


def _create_role(ctx: Any, statements: list[dict]) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-lambda-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_TAGS_KV)
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    managed_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn))

    if statements:
        policy_name = ctx.unique_name("sim2real-lambda-policy-")
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_function(
    ctx: Any, role_arn: str, handler_code: str, env: dict | None = None, timeout: int = 30
) -> str:
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-fn-")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("index.py", handler_code)
    zip_bytes = buf.getvalue()

    last_err: Exception | None = None
    deadline = time.monotonic() + 90
    created = False
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=timeout,
                Environment={"Variables": env or {}},
                Tags=_TAGS_MAP,
            )
            created = True
            break
        except lam.exceptions.InvalidParameterValueException as e:
            last_err = e
            time.sleep(3)
    if not created:
        raise AssertionError(f"function creation never succeeded (role propagation): {last_err}")

    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _wait_function_active(ctx, name)
    return name


def _wait_function_active(ctx: Any, name: str, timeout_s: float = 90.0) -> None:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg.get("State") == "Active":
            return
        time.sleep(2)
    raise AssertionError(f"function {name} never became Active")


def _invoke(ctx: Any, name: str, payload: dict | None = None) -> tuple[dict, Any]:
    lam = ctx.client("lambda")
    resp = lam.invoke(
        FunctionName=name,
        InvocationType="RequestResponse",
        Payload=json.dumps(payload or {}).encode("utf-8"),
    )
    body = json.loads(resp["Payload"].read())
    return resp, body


def _put_resource_policy_with_retry(sm: Any, secret_arn: str, policy: dict, timeout_s: float = 60.0) -> None:
    """Attach a resource policy, retrying MalformedPolicyDocumentException: a just-created role
    Principal may not have propagated in IAM yet."""
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            sm.put_resource_policy(SecretId=secret_arn, ResourcePolicy=json.dumps(policy))
            return
        except sm.exceptions.MalformedPolicyDocumentException as e:
            last_err = e
            time.sleep(3)
    raise AssertionError(f"put_resource_policy never succeeded (principal propagation): {last_err}")


def _create_secret(ctx: Any, secret_string: str, kms_key_id: str | None = None) -> str:
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-secret-")
    kwargs: dict[str, Any] = {"Name": name, "SecretString": secret_string, "Tags": _TAGS_KV}
    if kms_key_id:
        kwargs["KmsKeyId"] = kms_key_id
    resp = sm.create_secret(**kwargs)
    arn = resp["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=arn, ForceDeleteWithoutRecovery=True))
    return arn


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
