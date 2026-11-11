"""iam-role-wrong-trust-principal-lambda-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "iam-role-wrong-trust-principal-lambda-negative"
GROUP = "permission-boundary"
SERVICES = ["apigateway", "dynamodb", "lambda", "logs"]

_HANDLER_CODE = (
    "def handler(event, context):\n"
    "    return {'ok': True}\n"
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateFunction is rejected when the role's trust policy does not include lambda.amazonaws.com."""
    iam = ctx.client("iam")
    lam = ctx.client("lambda")

    bad_role_name = ctx.unique_name("sim2real-lambda-badtrust-")
    bad_role = iam.create_role(
        RoleName=bad_role_name,
        AssumeRolePolicyDocument=_trust_policy("ec2.amazonaws.com"),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    bad_role_arn = bad_role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=bad_role_name))

    func_name = ctx.unique_name("sim2real-lambda-badtrust-fn-")
    zip_bytes = _zip_bytes(_HANDLER_CODE)

    code, message = _client_error(
        lambda: lam.create_function(
            FunctionName=func_name,
            Runtime="python3.12",
            Role=bad_role_arn,
            Handler="index.handler",
            Code={"ZipFile": zip_bytes},
            Timeout=15,
        )
    )
    assert code == "InvalidParameterValueException", (
        f"CreateFunction with a role whose trust policy names only ec2.amazonaws.com must be "
        f"rejected with InvalidParameterValueException; got {code!r}"
    )
    assert message == "The role defined for the function cannot be assumed by Lambda.", message

    # effect absent: the function must not have been created
    absent_code, absent_message = _client_error(lambda: lam.get_function(FunctionName=func_name))
    assert absent_code == "ResourceNotFoundException", (
        f"the rejected CreateFunction must leave no function behind; get_function({func_name!r}) "
        f"expected ResourceNotFoundException, got {absent_code!r}"
    )
    assert absent_message == (
        f"Function not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{func_name}"
    ), absent_message

    # positive control: same call succeeds once trust is fixed to include lambda.amazonaws.com
    good_role_name = ctx.unique_name("sim2real-lambda-goodtrust-")
    good_role = iam.create_role(
        RoleName=good_role_name,
        AssumeRolePolicyDocument=_trust_policy("lambda.amazonaws.com"),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    good_role_arn = good_role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=good_role_name))

    resp = _create_function_with_retry(lam, func_name, good_role_arn, zip_bytes)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=func_name))
    assert resp["FunctionName"] == func_name, (
        f"CreateFunction with the corrected trust policy must succeed for the same function name; "
        f"expected {func_name!r}, got {resp.get('FunctionName')!r}"
    )

    got = lam.get_function(FunctionName=func_name)
    assert got["Configuration"]["FunctionName"] == func_name, (
        f"an independent get_function read must confirm the created function; expected "
        f"{func_name!r}, got {got['Configuration'].get('FunctionName')!r}"
    )


def _trust_policy(service: str) -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": service},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )


def _zip_bytes(code: str, filename: str = "index.py") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, code)
    return buf.getvalue()


def _create_function_with_retry(lam, name, role_arn, zip_bytes, timeout_s=90.0):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=15,
                Publish=True,
            )
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "InvalidParameterValueException" and "assume" in str(e).lower():
                last_err = e
                time.sleep(3)
                continue
            raise
    raise last_err if last_err else RuntimeError("create_function retry timeout")


def _client_error(fn):
    """Call fn(); return the (code, message) of its botocore error. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        error = e.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
