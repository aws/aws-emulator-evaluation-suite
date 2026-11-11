"""lambda-secretsmanager-resource-policy-deny-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-secretsmanager-resource-policy-deny-negative"
GROUP = "permission-boundary"
SERVICES = ["dynamodb", "lambda", "s3", "secretsmanager"]

_HANDLER_CODE = """
import boto3, json, os
from botocore.exceptions import ClientError

def handler(event, context):
    client = boto3.client("secretsmanager")
    try:
        resp = client.get_secret_value(SecretId=os.environ["SECRET_ARN"])
        return {"ok": True, "secret_string": resp.get("SecretString")}
    except ClientError as e:
        return {"ok": False, "error_code": e.response["Error"]["Code"]}
"""


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """A secret resource-policy Deny on a Lambda role blocks GetSecretValue with
    AccessDeniedException despite an identity-policy Allow; a sibling secret stays readable."""
    role_arn = _create_role(
        ctx,
        [{"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": "*"}],
    )

    denied_secret_value = "denied-secret-" + ctx.unique_name("")
    denied_arn = _create_secret(ctx, denied_secret_value)
    sm = ctx.client("secretsmanager")
    deny_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Principal": {"AWS": role_arn},
                "Action": "secretsmanager:GetSecretValue",
                "Resource": "*",
            }
        ],
    }
    _put_resource_policy_with_retry(sm, denied_arn, deny_policy)

    allowed_secret_value = "allowed-secret-" + ctx.unique_name("")
    allowed_arn = _create_secret(ctx, allowed_secret_value)

    fn_denied = _create_function(ctx, role_arn, _HANDLER_CODE, env={"SECRET_ARN": denied_arn})
    fn_allowed = _create_function(ctx, role_arn, _HANDLER_CODE, env={"SECRET_ARN": allowed_arn})

    body_denied = _poll_until(
        lambda: _invoke(ctx, fn_denied)[1],
        lambda b: b["ok"] is False,
        timeout_s=60.0,
        interval_s=3.0,
        description="the resource-policy Deny to take effect on GetSecretValue for the denied secret",
    )
    assert body_denied["ok"] is False, (
        f"the deny statement targets this role's ARN, so the real signed GetSecretValue call must "
        f"be refused; got ok={body_denied['ok']!r}"
    )
    assert body_denied["error_code"] == "AccessDeniedException", (
        f"expected AccessDeniedException for the resource-policy Deny, got "
        f"{body_denied['error_code']!r}"
    )
    assert "secret_string" not in body_denied, (
        f"the denied response must never carry the secret value; got {body_denied!r}"
    )

    body_allowed = _poll_until(
        lambda: _invoke(ctx, fn_allowed)[1],
        lambda b: b["ok"] is True,
        timeout_s=60.0,
        interval_s=3.0,
        description="the identity policy to grant GetSecretValue on the sibling secret with no deny statement",
    )
    assert body_allowed["ok"] is True, (
        f"the sibling secret carries no deny statement, so the same role must still succeed; got "
        f"ok={body_allowed['ok']!r}, error_code={body_allowed.get('error_code')!r}"
    )
    assert body_allowed["secret_string"] == allowed_secret_value, (
        f"expected the sibling secret's own value {allowed_secret_value!r}, got "
        f"{body_allowed['secret_string']!r} -- the deny must be scoped to the denied secret only"
    )


def _create_role(ctx: Any, statements: list[dict]) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-lambda-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
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
                Tags={"sim2real": CHECK},
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


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str):
    """Poll until predicate holds, raising on timeout; a resource-policy change is not enforced
    immediately."""
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not reached within {timeout_s}s; last observation {last!r}")
        time.sleep(interval_s)
        last = probe()
    return last


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
    kwargs: dict[str, Any] = {
        "Name": name,
        "SecretString": secret_string,
        "Tags": [{"Key": "sim2real", "Value": CHECK}],
    }
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
