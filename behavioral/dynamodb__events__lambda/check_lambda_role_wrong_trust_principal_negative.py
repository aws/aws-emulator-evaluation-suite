"""lambda-role-wrong-trust-principal-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-role-wrong-trust-principal-negative"
GROUP = "overly-permissive"
SERVICES = ["dynamodb", "events", "lambda"]

_HANDLER_STS = """
import boto3

def handler(event, context):
    sts = boto3.client("sts")
    ident = sts.get_caller_identity()
    return {"arn": ident["Arn"]}
"""


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """CreateFunction with a role trusting ec2.amazonaws.com is rejected with InvalidParameterValueException "The role
    defined for the function cannot be assumed by Lambda." and leaves no function; after only the trust policy
    is fixed, the same call succeeds and the function runs.
    """
    iam = ctx.client("iam")
    lam = ctx.client("lambda")

    role_name = ctx.unique_name("sim2real-lambda-trust-bad-")
    role_arn = _create_role(ctx, iam, role_name, "ec2.amazonaws.com")

    func_name = ctx.unique_name("sim2real-lambda-trust-bad-fn-")
    code = _zip_lambda_code(_HANDLER_STS)
    create_kwargs = dict(
        FunctionName=func_name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="index.handler",
        Code={"ZipFile": code},
        Timeout=15,
        Tags={"sim2real:managed": "true"},
    )

    def _try_create():
        lam.create_function(**create_kwargs)

    code_seen, message_seen = _error(_try_create)
    assert code_seen == "InvalidParameterValueException", (code_seen, message_seen)
    assert message_seen == "The role defined for the function cannot be assumed by Lambda.", message_seen

    not_found_code, not_found_message = _error(lambda: lam.get_function(FunctionName=func_name))
    assert not_found_code == "ResourceNotFoundException", (not_found_code, not_found_message)
    account_id = role_arn.split(":")[4]
    expected_arn = f"arn:aws:lambda:{ctx.region}:{account_id}:function:{func_name}"
    assert not_found_message == f"Function not found: {expected_arn}", not_found_message

    # Restore: fix ONLY the trust policy on the same role (name, permissions and the
    # CreateFunction call all stay identical), then demand the identical call succeeds.
    iam.update_assume_role_policy(RoleName=role_name, PolicyDocument=_trust_policy("lambda.amazonaws.com"))
    _create_function_with_retry(lam, **create_kwargs)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=func_name))
    _wait_active(lam, func_name)
    invoke_resp = lam.invoke(FunctionName=func_name, InvocationType="RequestResponse")
    assert invoke_resp["StatusCode"] == 200, invoke_resp
    assert "FunctionError" not in invoke_resp, invoke_resp


def _trust_policy(principal_service: str) -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": principal_service}, "Action": "sts:AssumeRole"}
            ],
        }
    )


def _create_role(ctx, iam, role_name: str, principal_service: str) -> str:
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_trust_policy(principal_service),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    role_arn = resp["Role"]["Arn"]

    def _cleanup():
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _zip_lambda_code(handler_src: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", handler_src)
    return buf.getvalue()


def _create_function_with_retry(lam, *, timeout_s: float = 90.0, interval_s: float = 3.0, **kwargs: Any):
    deadline = time.monotonic() + timeout_s
    last_exc: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            msg = exc.response["Error"].get("Message", "")
            if code == "InvalidParameterValueException" and "cannot be assumed" in msg:
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    assert last_exc is not None
    raise last_exc


def _wait_active(lam, func_name: str, timeout_s: float = 60.0, interval_s: float = 2.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if lam.get_function(FunctionName=func_name)["Configuration"]["State"] == "Active":
            return
        time.sleep(interval_s)
    raise AssertionError(f"function {func_name} never became Active")


def _error(fn) -> tuple[str, str]:
    """Return (Error.Code, Error.Message) of the refusal fn raises; raise if fn succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected rejection but call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
