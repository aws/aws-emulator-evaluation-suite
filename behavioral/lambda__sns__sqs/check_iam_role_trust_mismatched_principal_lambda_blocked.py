"""iam-role-trust-mismatched-principal-lambda-blocked."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags

CHECK = "iam-role-trust-mismatched-principal-lambda-blocked"
GROUP = "trust-policy"
SERVICES = ["lambda", "sns", "sqs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateFunction rejects a role whose trust policy names sqs.amazonaws.com
    instead of lambda.amazonaws.com (Lambda cannot assume it), leaves no function
    behind, while the identical call with a correctly-trusting role succeeds."""
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    code = _lambda_zip("def handler(event, context):\n    return {'ok': True}\n")

    tags_kv = [{"Key": "sim2real:managed", "Value": "true"}]
    tags_map = {"sim2real:managed": "true"}

    # --- broken: role trusts the wrong service principal ---
    bad_role_name = ctx.unique_name("sim2real-behav-badrole-")
    bad_role_arn = iam.create_role(
        RoleName=bad_role_name,
        AssumeRolePolicyDocument=json.dumps(_trust_doc(["sqs.amazonaws.com"])),
        Tags=tags_kv,
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=bad_role_name))

    bad_fn_name = ctx.unique_name("sim2real-behav-badfn-")
    code_err, message = _client_error(
        lambda: lam.create_function(
            FunctionName=bad_fn_name,
            Runtime="python3.12",
            Role=bad_role_arn,
            Handler="lambda_function.handler",
            Code={"ZipFile": code},
            Timeout=15,
            Tags=tags_map,
        )
    )
    assert code_err == "InvalidParameterValueException", f"got {code_err}"
    assert message == "The role defined for the function cannot be assumed by Lambda.", (
        f"got message {message!r}"
    )

    # effect absent: no function was created
    got, message = _client_error(lambda: lam.get_function(FunctionName=bad_fn_name))
    assert got == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for the never-created function, got {got!r}"
    )
    expected = f"Function not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{bad_fn_name}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # --- positive control: same call, correctly-trusting role, succeeds ---
    good_role_name = ctx.unique_name("sim2real-behav-goodrole-")
    good_role_arn = iam.create_role(
        RoleName=good_role_name,
        AssumeRolePolicyDocument=json.dumps(_trust_doc(["lambda.amazonaws.com"])),
        Tags=tags_kv,
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=good_role_name))

    good_fn_name = ctx.unique_name("sim2real-behav-goodfn-")
    fn_arn = _create_function_with_retry(lam, good_role_arn, good_fn_name, code, tags=tags_map)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=good_fn_name))
    assert fn_arn, "create_function did not return a FunctionArn for the correctly-trusting role"
    _wait_function_active(lam, good_fn_name)

    # terminal read: an independent Invoke, not a status word -- proves the function is
    # genuinely usable (the role was actually assumable), not merely provisioned.
    invoke = lam.invoke(FunctionName=good_fn_name, Payload=b"{}")
    assert invoke["StatusCode"] == 200, f"invoke returned StatusCode {invoke['StatusCode']!r}"
    assert "FunctionError" not in invoke, (
        f"the correctly-trusting role's function failed to execute: {invoke.get('FunctionError')!r}"
    )
    payload = json.loads(invoke["Payload"].read())
    assert payload == {"ok": True}, (
        f"expected the correctly-trusting role's function to run and return {{'ok': True}}, "
        f"got {payload!r}"
    )


def _trust_doc(services: list[str]) -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": services},
                "Action": "sts:AssumeRole",
            }
        ],
    }


def _lambda_zip(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", code)
    return buf.getvalue()


def _client_error(fn) -> tuple[str, str]:
    """The (Code, Message) of the ClientError fn() raises; a success raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _create_function_with_retry(
    lam,
    role_arn: str,
    fn_name: str,
    code_bytes: bytes,
    timeout_s: float = 60.0,
    tags: dict[str, str] | None = None,
) -> str:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            resp = lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": code_bytes},
                Timeout=15,
                Tags=tags or {},
            )
            return resp["FunctionArn"]
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "InvalidParameterValueException" and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise
    raise AssertionError("CreateFunction never succeeded")


def _wait_function_active(lam, fn_name: str, timeout_s: float = 60.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=fn_name)
        if cfg["State"] == "Active":
            return
        if cfg["State"] == "Failed":
            raise AssertionError(f"function entered Failed state: {cfg}")
        time.sleep(2)
    raise AssertionError("function never became Active")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
