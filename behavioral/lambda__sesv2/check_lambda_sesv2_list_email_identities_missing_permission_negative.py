"""lambda-sesv2-list-email-identities-missing-permission-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-sesv2-list-email-identities-missing-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["lambda", "sesv2"]

_HANDLER_SRC = '''
import boto3
from botocore.exceptions import ClientError

def handler(event, context):
    client = boto3.client("sesv2")
    target = event.get("identity")
    try:
        next_token = None
        found = False
        names = []
        while True:
            kwargs = {"NextToken": next_token} if next_token else {}
            resp = client.list_email_identities(PageSize=10, **kwargs)
            for item in resp.get("EmailIdentities", []):
                name = item.get("IdentityName")
                names.append(name)
                if name == target:
                    found = True
            if found:
                break
            next_token = resp.get("NextToken")
            if not next_token:
                break
        return {"ok": True, "identities": names, "found": found}
    except ClientError as e:
        return {"ok": False, "error_code": e.response["Error"]["Code"]}
'''


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda role without ses:ListEmailIdentities gets AccessDeniedException and returns no
    identity data; a role that has the permission still succeeds and actually observes a
    real identity created outside the function, not merely an empty list."""
    identity = f"{ctx.unique_name('sim2real-sesv2lam-list-')}@example.com"
    ses = ctx.client("sesv2")
    ses.create_email_identity(EmailIdentity=identity)
    ctx.on_cleanup(lambda: _delete_identity_ignore(ctx, identity))

    _, denied_role_arn = _create_role(ctx, "lambda.amazonaws.com", [])
    denied_fn = _create_function(ctx, denied_role_arn, _HANDLER_SRC)
    denied_result = _invoke(ctx, denied_fn, {"identity": identity})
    assert denied_result["ok"] is False, f"expected denied invoke to fail, got {denied_result}"
    assert denied_result["error_code"] == "AccessDeniedException", (
        f"expected AccessDeniedException, got {denied_result}"
    )
    assert "identities" not in denied_result, f"expected no identity data on denial, got {denied_result}"

    _, allowed_role_arn = _create_role(
        ctx, "lambda.amazonaws.com", [{"Effect": "Allow", "Action": "ses:ListEmailIdentities", "Resource": "*"}]
    )
    allowed_fn = _create_function(ctx, allowed_role_arn, _HANDLER_SRC)
    allowed_result = _invoke(ctx, allowed_fn, {"identity": identity})
    assert allowed_result["ok"] is True, f"expected allowed invoke to succeed, got {allowed_result}"
    assert isinstance(allowed_result["identities"], list), f"expected a list of identities, got {allowed_result}"
    assert allowed_result["found"] is True, (
        f"expected {identity} to be visible via ListEmailIdentities with the grant, got {allowed_result}"
    )


def _delete_identity_ignore(ctx, identity: str) -> None:
    try:
        ctx.client("sesv2").delete_email_identity(EmailIdentity=identity)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _zip_lambda_code(handler_src: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", handler_src)
    return buf.getvalue()


def _create_role(ctx, principal_service: str, statements: list[dict[str, Any]]) -> tuple[str, str]:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sesv2lam-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": principal_service}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    basic_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn))
    if statements:
        policy_name = f"{role_name}-inline"
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_name, role_arn


def _wait_active(ctx, function_name: str, timeout_s: float = 90.0) -> None:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=function_name)
        state = cfg.get("State")
        if state == "Active":
            return
        if state == "Failed":
            raise AssertionError(f"function {function_name} failed to become active: {cfg}")
        time.sleep(2)
    raise AssertionError(f"function {function_name} never became Active within {timeout_s}s")


def _create_function(ctx, role_arn: str, handler_src: str, timeout_s: float = 90.0) -> str:
    lam = ctx.client("lambda")
    function_name = ctx.unique_name("sim2real-sesv2lam-fn-")
    zip_bytes = _zip_lambda_code(handler_src)
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ctx.on_cleanup(lambda _n=function_name: _delete_lambda_log_group(ctx, _n))
            lam.create_function(
                FunctionName=function_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=30,
                MemorySize=128,
            )
            break
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "InvalidParameterValueException" and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=function_name))
    _wait_active(ctx, function_name)
    return function_name


def _invoke(ctx, function_name: str, payload: dict[str, Any]) -> dict[str, Any]:
    lam = ctx.client("lambda")
    resp = lam.invoke(FunctionName=function_name, Payload=json.dumps(payload).encode("utf-8"))
    raw = resp["Payload"].read()
    body = json.loads(raw) if raw else {}
    if resp.get("FunctionError"):
        raise AssertionError(f"lambda invocation raised {resp['FunctionError']}: {body}")
    return body


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
