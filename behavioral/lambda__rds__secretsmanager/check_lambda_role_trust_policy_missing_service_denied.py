"""lambda-role-trust-policy-missing-service-denied."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-role-trust-policy-missing-service-denied"
GROUP = "permission-boundary"
SERVICES = ["lambda", "rds", "secretsmanager"]

_HANDLER_CODE = """
def handler(event, context):
    return {"result": "ok"}
"""


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """CreateFunction refuses a role whose trust policy names no service principal with
    InvalidParameterValueException (exact message) and creates no function; adding lambda.amazonaws.com
    to the same role's trust policy lets the same call create a function that invokes."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    lam = ctx.client("lambda")
    account_id = sts.get_caller_identity()["Account"]

    # --- broken role: trusts only the AWS account, never lambda.amazonaws.com ---
    role_name = ctx.unique_name("sim2real-lambda-trust-missing-")
    bad_trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(bad_trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    basic_exec_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_exec_arn)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_exec_arn)
    )

    function_name = ctx.unique_name("sim2real-lambda-trust-missing-fn-")
    zip_bytes = _make_lambda_zip(_HANDLER_CODE)
    create_kwargs: dict[str, Any] = dict(
        FunctionName=function_name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="index.handler",
        Code={"ZipFile": zip_bytes},
        Timeout=15,
        MemorySize=128,
        Tags={"sim2real": CHECK},
    )

    code, message = _error_code(lambda: lam.create_function(**create_kwargs))
    assert code == "InvalidParameterValueException", (
        f"CreateFunction must reject a role whose trust policy names no service "
        f"principal with InvalidParameterValueException; got {code!r}: {message!r}"
    )
    assert message == "The role defined for the function cannot be assumed by Lambda.", (
        f"unexpected CreateFunction refusal message: {message!r}"
    )

    # effect absent: the function was never actually created
    not_found_code, not_found_message = _error_code(lambda: lam.get_function(FunctionName=function_name))
    assert not_found_code == "ResourceNotFoundException", (
        f"a function rejected at creation must not exist; GetFunction got {not_found_code!r}: "
        f"{not_found_message!r}"
    )
    function_arn = f"arn:aws:lambda:{ctx.region}:{account_id}:function:{function_name}"
    assert not_found_message == f"Function not found: {function_arn}", (
        f"unexpected GetFunction not-found message: {not_found_message!r}"
    )

    # --- restore: the SAME role, now also naming lambda.amazonaws.com. The role's
    # identity (ARN), attached policy and every other property are untouched, so the
    # trust policy is the only variable this leg can be attributing the recovery to.
    good_trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    iam.update_assume_role_policy(
        RoleName=role_name, PolicyDocument=json.dumps(good_trust_policy)
    )
    fetched_policy = iam.get_role(RoleName=role_name)["Role"]["AssumeRolePolicyDocument"]
    assert fetched_policy == good_trust_policy, (
        f"the trust policy must read back as updated before anything is concluded from "
        f"the retry; expected {good_trust_policy!r}, got {fetched_policy!r}"
    )

    _create_function_with_retry(ctx, lam, **create_kwargs)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=function_name))
    _wait_function_active(ctx, lam, function_name)

    invoke_resp = lam.invoke(FunctionName=function_name, Payload=b"{}")
    assert invoke_resp["StatusCode"] == 200, (
        f"the identical CreateFunction call must now succeed and be invokable; "
        f"got StatusCode {invoke_resp['StatusCode']!r}"
    )
    assert "FunctionError" not in invoke_resp, (
        f"the invoke must not report a FunctionError once the trust policy is fixed; "
        f"got {invoke_resp.get('FunctionError')!r}"
    )
    payload = json.loads(invoke_resp["Payload"].read())
    assert payload == {"result": "ok"}, (
        f"the restored function must execute its real handler; got payload {payload!r}"
    )


def _make_lambda_zip(handler_code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", handler_code)
    return buf.getvalue()


def _error_code(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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
    assert last_err is not None
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
