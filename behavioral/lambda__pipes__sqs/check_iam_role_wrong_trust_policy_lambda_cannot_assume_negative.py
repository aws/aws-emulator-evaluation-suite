"""iam-role-wrong-trust-policy-lambda-cannot-assume-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "iam-role-wrong-trust-policy-lambda-cannot-assume-negative"
GROUP = "overly-permissive"
SERVICES = ["lambda", "pipes", "sqs"]

_HANDLER_CODE = (
    "def handler(event, context):\n"
    "    return {'ok': True}\n"
)


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A role that trusts only sqs.amazonaws.com cannot be assumed by Lambda: creating a
    function with that role is rejected, no function is left behind, and (as an in-file
    positive control) the identical flow with a correctly-trusted role succeeds."""
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    zip_bytes = _lambda_zip_bytes(_HANDLER_CODE)

    # --- broken: role trusts sqs.amazonaws.com, not lambda.amazonaws.com ---
    bad_role_name = ctx.unique_name("sim2real-badtrust-role-")
    bad_role = iam.create_role(
        RoleName=bad_role_name,
        AssumeRolePolicyDocument=json.dumps(_trust_policy("sqs.amazonaws.com")),
    )
    bad_role_arn = bad_role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=bad_role_name))

    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=bad_role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=bad_role_name, PolicyArn=policy_arn))

    # Make sure the role itself is visible before attempting, so the failure we observe
    # is attributable to the trust mismatch and not to role-creation propagation delay.
    _poll_until(lambda: _role_exists(iam, bad_role_name), lambda ok: ok, timeout_s=20, interval_s=1)

    bad_function_name = ctx.unique_name("sim2real-badtrust-fn-")
    code, message = _error_code(
        lambda: lam.create_function(
            FunctionName=bad_function_name,
            Runtime="python3.12",
            Role=bad_role_arn,
            Handler="index.handler",
            Code={"ZipFile": zip_bytes},
            Timeout=15,
            MemorySize=128,
        )
    )
    assert code == "InvalidParameterValueException", f"{code!r}: {message!r}"
    assert message == "The role defined for the function cannot be assumed by Lambda.", message

    not_found_code, not_found_message = _error_code(lambda: lam.get_function(FunctionName=bad_function_name))
    assert not_found_code == "ResourceNotFoundException", f"{not_found_code!r}: {not_found_message!r}"
    bad_function_arn = f"arn:aws:lambda:{ctx.region}:{ctx.account}:function:{bad_function_name}"
    assert not_found_message == f"Function not found: {bad_function_arn}", not_found_message

    # --- positive control: identical flow with the correct trust principal ---
    good_role_name = ctx.unique_name("sim2real-goodtrust-role-")
    good_role = iam.create_role(
        RoleName=good_role_name,
        AssumeRolePolicyDocument=json.dumps(_trust_policy("lambda.amazonaws.com")),
    )
    good_role_arn = good_role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=good_role_name))
    iam.attach_role_policy(RoleName=good_role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=good_role_name, PolicyArn=policy_arn))

    good_function_name = ctx.unique_name("sim2real-goodtrust-fn-")
    _create_function_with_retry(
        lam,
        FunctionName=good_function_name,
        Runtime="python3.12",
        Role=good_role_arn,
        Handler="index.handler",
        Code={"ZipFile": zip_bytes},
        Timeout=15,
        MemorySize=128,
    )
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=good_function_name))

    final_state = _poll_until(
        lambda: lam.get_function(FunctionName=good_function_name)["Configuration"]["State"],
        lambda state: state in ("Active", "Failed"),
        timeout_s=60,
        interval_s=2,
    )
    assert final_state == "Active", f"control function never became Active: {final_state}"

    invoke_resp = lam.invoke(FunctionName=good_function_name)
    assert invoke_resp["StatusCode"] == 200, f"expected StatusCode 200, got {invoke_resp['StatusCode']}"
    assert "FunctionError" not in invoke_resp, f"invocation reported FunctionError: {invoke_resp.get('FunctionError')}"


def _trust_policy(service_principal: str) -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": service_principal},
                "Action": "sts:AssumeRole",
            }
        ],
    }


def _lambda_zip_bytes(handler_code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", handler_code)
    return buf.getvalue()


def _role_exists(iam, role_name: str) -> bool:
    try:
        iam.get_role(RoleName=role_name)
        return True
    except ClientError:
        return False


def _error_code(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_function_with_retry(lam, *, attempts: int = 15, delay_s: float = 2.0, **kwargs):
    last_err = None
    for _ in range(attempts):
        try:
            return lam.create_function(**kwargs)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            msg = e.response["Error"].get("Message", "")
            if code == "InvalidParameterValueException" and "cannot be assumed" in msg:
                last_err = e
                time.sleep(delay_s)
                continue
            raise
    raise last_err


def _poll_until(probe, predicate, *, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    value = None
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    raise TimeoutError(f"timed out after {timeout_s}s waiting on predicate; last value: {value!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
