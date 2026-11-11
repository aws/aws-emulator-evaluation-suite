"""lambda-execution-role-assumed-for-rds-proxy-auth-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-execution-role-assumed-for-rds-proxy-auth-positive"
GROUP = "iam-trust"
SERVICES = ["lambda", "rds", "secretsmanager"]

# Lambda functions that back RDS Proxy IAM-authenticated connections run under their
# own execution role (trusted by lambda.amazonaws.com); the RDS SDK call to mint the
# proxy connection auth token is signed with THAT assumed role's credentials, not the
# caller's. `generate_db_auth_token` never leaves the SDK (it locally presigns a SigV4
# URL), so the token's own bytes cannot prove anything about the target by themselves -
# any credentials produce a well-formed token for any hostname. What CAN be proven
# without a live DB/proxy (a separate, cost-gated concern - RDS Proxy provisioning
# takes ~15-20 min - intentionally out of scope here) is that the token was signed by
# the SAME session get_caller_identity just reported as the assumed role: the token's
# embedded X-Amz-Credential access key must equal this invocation's own frozen
# credential, and that credential must carry a session token (not a static one). A
# target that fakes role assumption - e.g. handing every function the same long-lived
# key regardless of its execution role - fails that link even though it can still
# return a plausible-looking ARN and a plausible-looking token independently.
_HANDLER_CODE = """
import boto3


def handler(event, context):
    session = boto3.Session()
    creds = session.get_credentials().get_frozen_credentials()
    sts = session.client("sts")
    identity = sts.get_caller_identity()
    rds = session.client("rds")
    token = rds.generate_db_auth_token(
        DBHostname=event["host"], Port=event.get("port", 3306), DBUsername=event["user"]
    )
    return {
        "arn": identity["Arn"],
        "access_key_id": creds.access_key,
        "has_session_token": bool(creds.token),
        "token": token,
    }
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda execution role trusted by lambda.amazonaws.com is assumed for real when
    the function runs, and the RDS IAM auth token it mints for an RDS Proxy endpoint is
    signed by that SAME assumed-role session - not by some other, static identity."""
    iam = ctx.client("iam")
    lam = ctx.client("lambda")

    role_name = ctx.unique_name("sim2real-lambda-rdsauth-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    basic_exec_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_exec_arn)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_exec_arn)
    )

    inline_policy_name = "rds-proxy-connect"
    rds_connect_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "rds-db:connect", "Resource": "*"}
        ],
    }
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=inline_policy_name,
        PolicyDocument=json.dumps(rds_connect_policy),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=inline_policy_name)
    )

    function_name = ctx.unique_name("sim2real-lambda-rdsauth-fn-")
    zip_bytes = _make_lambda_zip(_HANDLER_CODE)
    _create_function_with_retry(
        ctx,
        lam,
        FunctionName=function_name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="index.handler",
        Code={"ZipFile": zip_bytes},
        Timeout=15,
        MemorySize=128,
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=function_name))
    _wait_function_active(ctx, lam, function_name)

    proxy_host = f"{ctx.unique_name('sim2real-proxy-')}.proxy-abcdef.{ctx.region}.rds.amazonaws.com"
    invoke_resp = lam.invoke(
        FunctionName=function_name,
        Payload=json.dumps({"host": proxy_host, "port": 3306, "user": "app_user"}).encode(
            "utf-8"
        ),
    )
    assert invoke_resp["StatusCode"] == 200, invoke_resp
    assert "FunctionError" not in invoke_resp, invoke_resp
    result = json.loads(invoke_resp["Payload"].read())

    assert f":assumed-role/{role_name}/" in result["arn"], result["arn"]
    assert result["has_session_token"] is True, (
        "the RDS auth token was minted from credentials with no session token behind them - "
        "these are static/long-lived credentials, not the Lambda's assumed-role session"
    )
    token = result["token"]
    assert len(token) > 100, f"auth token implausibly short ({len(token)} chars): {token!r}"
    assert token.startswith(f"{proxy_host}:3306/?Action=connect"), token
    access_key_id = result["access_key_id"]
    assert f"X-Amz-Credential={access_key_id}%2F" in token, (
        f"auth token was signed with access key {access_key_id!r} matching some OTHER "
        f"query param than expected, or a different key entirely: {token!r}"
    )


def _make_lambda_zip(handler_code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", handler_code)
    return buf.getvalue()


def _create_function_with_retry(ctx, lam, timeout_s: float = 60.0, **kwargs: Any):
    deadline = time.monotonic() + timeout_s
    last_err: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return lam.create_function(**kwargs)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            msg = e.response["Error"].get("Message", "")
            if code == "InvalidParameterValueException" and "cannot be assumed" in msg:
                last_err = e
                time.sleep(3)
                continue
            raise
    assert last_err is not None, "retry loop exited without ever observing the expected error"
    raise last_err


def _wait_function_active(ctx, lam, function_name: str, timeout_s: float = 60.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=function_name)
        if cfg["State"] == "Active":
            return
        if cfg["State"] == "Failed":
            raise AssertionError(f"function entered Failed state: {cfg}")
        time.sleep(2)
    raise AssertionError(f"function {function_name} never became Active within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
