"""update-function-configuration-dead-letter-target-arn-pattern-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-function-configuration-dead-letter-target-arn-pattern-rejected"
GROUP = "event-invoke-config"
SERVICES = ["iam", "lambda"]

_PREFIX = "sim2real-"
_ROLE_PROPAGATION_S = 90

_HANDLER_CODE = "def handler(event, context):\n    return event\n"


def _xname(ctx, kind: str) -> str:
    return ctx.unique_name(f"{_PREFIX}{kind}-")


def _teardown(undo, *not_found: str):
    """Run ``undo()``; only the resource's own not-found codes mean it is already gone."""

    def run() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run


def _zip_of(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _wait_active(lam, name: str, timeout_s: float = 90.0) -> None:
    deadline = time.monotonic() + timeout_s
    last: dict = {}
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=name)
        if last.get("State") == "Failed":
            raise AssertionError(f"function {name!r} entered Failed: {last.get('StateReason')!r}")
        if last.get("State") == "Active":
            return
        time.sleep(2)
    raise AssertionError(f"function {name!r} never became Active: {last!r}")


def _error_code(fn) -> tuple[str, str]:
    """The (code, message) ``fn`` raises; an unexpected success raises too, naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", "<no code>"), err.get("Message", "<no message>")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateFunctionConfiguration refuses a DeadLetterConfig.TargetArn that fails the ARN
    pattern with a ValidationException, and the function's own DeadLetterConfig stays unchanged;
    an empty TargetArn, the pattern's other legal form, is accepted.

    Reference: https://docs.aws.amazon.com/lambda/latest/api/API_UpdateFunctionConfiguration.html
    """
    lam = ctx.client("lambda")
    iam = ctx.client("iam")

    role_name = _xname(ctx, "role")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]

    def _delete_role() -> None:
        for policy_name in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_delete_role)
    iam.put_role_policy(
        RoleName=role_name, PolicyName="exec", PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                           "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                           "Resource": "*"}],
        }),
    )

    fn_name = _xname(ctx, "fn")
    create_deadline = time.monotonic() + _ROLE_PROPAGATION_S
    while True:
        try:
            lam.create_function(
                FunctionName=fn_name, Runtime="python3.12", Role=role_arn,
                Handler="index.handler", Code={"ZipFile": _zip_of(_HANDLER_CODE)},
                Timeout=10, MemorySize=128,
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterValueException" \
                    or time.monotonic() > create_deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=fn_name),
                             "ResourceNotFoundException"))
    _wait_active(lam, fn_name)

    # Positive control: the pattern's other legal form, an empty TargetArn, is accepted.
    lam.update_function_configuration(FunctionName=fn_name, DeadLetterConfig={"TargetArn": ""})
    _wait_active(lam, fn_name)
    before = lam.get_function_configuration(FunctionName=fn_name)
    assert before.get("DeadLetterConfig", {}).get("TargetArn", "") == "", (
        f"an empty TargetArn must be accepted and read back empty, got "
        f"{before.get('DeadLetterConfig')!r}"
    )

    bad_arn = "not-an-arn"
    code, message = _error_code(
        lambda: lam.update_function_configuration(
            FunctionName=fn_name, DeadLetterConfig={"TargetArn": bad_arn},
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message!r}"
    expected_message = (
        f"1 validation error detected: Value '{bad_arn}' at 'deadLetterConfig.targetArn' "
        "failed to satisfy constraint: Member must satisfy regular expression pattern: "
        r"(arn:(aws[a-zA-Z-]*)?:[a-z0-9-.]+:.*)|()"
    )
    assert message == expected_message, f"expected the exact message {expected_message!r}, got {message!r}"

    # The rejected call had no effect: DeadLetterConfig still reads the empty value from before.
    after = lam.get_function_configuration(FunctionName=fn_name)
    assert after.get("DeadLetterConfig", {}).get("TargetArn", "") == "", (
        f"the rejected update must leave DeadLetterConfig unchanged, got "
        f"{after.get('DeadLetterConfig')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
