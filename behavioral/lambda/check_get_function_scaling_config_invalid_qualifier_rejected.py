"""get-function-scaling-config-invalid-qualifier-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-function-scaling-config-invalid-qualifier-rejected"
GROUP = "error-semantics"
SERVICES = ["lambda"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetFunctionScalingConfig with a qualifier outside the [A-Za-z0-9$_-] pattern is rejected
    with ValidationException, distinct from the AccessDeniedException a real version without a
    capacity-provider scaling config gets."""
    lam = ctx.client("lambda")
    fn_name = _create_basic_function(ctx)
    version = lam.publish_version(FunctionName=fn_name)["Version"]

    # positive control: a syntactically valid qualifier on the real function
    # resolves the function/version and fails only on "not configured for
    # scaling", never a parameter-validation style error.
    existing_code, existing_message = _error(
        lambda: lam.get_function_scaling_config(FunctionName=fn_name, Qualifier=version)
    )
    assert existing_code == "AccessDeniedException", existing_code
    assert existing_message == (
        "The function provided by the arn does not contain a capacity provider configuration"
    ), existing_message

    # negative: "not a valid qualifier!" contains characters outside the
    # documented Qualifier pattern and must be rejected as a bad parameter,
    # not silently coerced to $LATEST or treated as a lookup miss.
    code, message = _error(
        lambda: lam.get_function_scaling_config(
            FunctionName=fn_name, Qualifier="not a valid qualifier!"
        )
    )
    assert code == "ValidationException", code
    assert message == (
        "1 validation error detected: Value 'not a valid qualifier!' at 'qualifier' failed to "
        "satisfy constraint: Member must satisfy regular expression pattern: "
        "(\\$LATEST\\.PUBLISHED|[0-9]+)"
    ), message


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
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
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
