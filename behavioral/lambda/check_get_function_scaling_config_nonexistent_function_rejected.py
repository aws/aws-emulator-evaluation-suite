"""get-function-scaling-config-nonexistent-function-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-function-scaling-config-nonexistent-function-rejected"
GROUP = "error-semantics"
SERVICES = ["lambda"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetFunctionScalingConfig for a never-created function raises ResourceNotFoundException,
    distinct from the AccessDeniedException a real function without a scaling config gets."""
    lam = ctx.client("lambda")
    fn_name = _create_basic_function(ctx)
    version = lam.publish_version(FunctionName=fn_name)["Version"]

    # positive control: the function+version genuinely resolves, so the failure
    # here is specifically "not configured for capacity-provider scaling", never
    # a resource-not-found style error.
    existing_code, existing_message = _error(
        lambda: lam.get_function_scaling_config(FunctionName=fn_name, Qualifier=version)
    )
    assert existing_code == "AccessDeniedException", (
        f"expected AccessDeniedException for a resolvable function with no capacity-provider "
        f"scaling config, got {existing_code!r}"
    )
    assert existing_message == (
        "The function provided by the arn does not contain a capacity provider configuration"
    ), existing_message

    # negative: the function name was never created at all
    missing_name = ctx.unique_name("sim2real-lambda-missing-fn-")
    code, message = _error(
        lambda: lam.get_function_scaling_config(FunctionName=missing_name, Qualifier="1")
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a function name that was never created, got {code!r}"
    )
    assert message == "The resource you requested does not exist.", message


def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _zip_bytes(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("lambda_function.py", code)
    return buf.getvalue()


def _create_basic_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-lambda-exec-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role_arn


def _create_basic_function(ctx):
    lam = ctx.client("lambda")
    role_arn = _create_basic_role(ctx)
    fn_name = ctx.unique_name("sim2real-lambda-fn-")
    code = "def handler(event, context):\n    return {'ok': True}\n"

    def _try_create():
        try:
            lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": _zip_bytes(code)},
                Timeout=10,
                Tags={"sim2real:managed": "true"},
            )
            return True
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidParameterValueException":
                return False  # execution role not yet propagated to Lambda
            raise

    _poll_until(_try_create, lambda ok: ok, timeout_s=60.0, interval_s=3.0)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    _poll_until(
        lambda: lam.get_function(FunctionName=fn_name)["Configuration"]["State"],
        lambda s: s == "Active",
        timeout_s=60.0,
        interval_s=2.0,
    )
    return fn_name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
