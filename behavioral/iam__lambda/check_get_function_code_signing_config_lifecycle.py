"""get-function-code-signing-config-lifecycle."""
from __future__ import annotations

import io
import json
import time
import uuid
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-function-code-signing-config-lifecycle"
GROUP = "code_signing"
SERVICES = ["iam", "lambda"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _detach_ignore(lam, function_name: str) -> None:
    try:
        lam.delete_function_code_signing_config(FunctionName=function_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in (
            "CodeSigningConfigNotFoundException",
            "ResourceNotFoundException",
        ):
            raise


def _delete_csc_ignore_not_found(lam, csc_arn: str) -> None:
    try:
        lam.delete_code_signing_config(CodeSigningConfigArn=csc_arn)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _lambda_zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", "def handler(event, context):\n    return {'ok': True}\n")
    return buf.getvalue()


def _create_exec_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role["Role"]["Arn"]


def _create_function(ctx, lam, role_arn: str) -> str:
    name = ctx.unique_name("sim2real-behav-fn-")
    deadline = time.monotonic() + 90
    resp = None
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": _lambda_zip_bytes()},
                Timeout=10,
                MemorySize=128,
                Publish=False,
                Tags={"sim2real:managed": "true"},
            )
            break
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if (err.get("Code") == "InvalidParameterValueException"
                    and "cannot be assumed" in err.get("Message", "")
                    and time.monotonic() < deadline):
                time.sleep(3)
                continue
            raise
    if resp is None:
        raise AssertionError("create_function never succeeded (role propagation timeout)")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _wait_active(lam, name)
    return name


def _wait_active(lam, name: str, timeout_s: float = 90) -> None:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=name)
        if last["State"] == "Active":
            return
        if last["State"] == "Failed":
            raise AssertionError(f"function entered Failed: {last.get('StateReason')}")
        time.sleep(2)
    raise AssertionError(f"{name} did not become Active in time; last={last!r}")


def _fake_signing_profile_arn(ctx) -> str:
    return (
        f"arn:aws:signer:{ctx.region}:{ctx.account}:/signing-profiles/"
        f"SimRealGetCscProfile{uuid.uuid4().hex[:8]}/1"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetFunctionCodeSigningConfig answers 200 with neither field for an unattached function,
    exactly the attached config's ARN and the function's name once one is attached, and
    ResourceNotFoundException with the exact message for a function that was never created.
    """
    lam = ctx.client("lambda")
    role_arn = _create_exec_role(ctx)
    fn = _create_function(ctx, lam, role_arn)

    before = lam.get_function_code_signing_config(FunctionName=fn)
    assert "CodeSigningConfigArn" not in before, (
        f"expected no CodeSigningConfigArn before any config is attached, got {before!r}"
    )
    assert "FunctionName" not in before, (
        f"expected no FunctionName before any config is attached, got {before!r}"
    )

    csc = lam.create_code_signing_config(
        AllowedPublishers={"SigningProfileVersionArns": [_fake_signing_profile_arn(ctx)]},
        Tags={"sim2real-check": CHECK},
    )
    csc_arn = csc["CodeSigningConfig"]["CodeSigningConfigArn"]
    ctx.on_cleanup(lambda: _delete_csc_ignore_not_found(lam, csc_arn))

    lam.put_function_code_signing_config(CodeSigningConfigArn=csc_arn, FunctionName=fn)
    ctx.on_cleanup(lambda: _detach_ignore(lam, fn))

    attached = lam.get_function_code_signing_config(FunctionName=fn)
    assert attached["CodeSigningConfigArn"] == csc_arn, (
        f"expected CodeSigningConfigArn {csc_arn!r} once attached, got {attached!r}"
    )
    assert attached["FunctionName"] == fn, (
        f"expected FunctionName {fn!r} once attached, got {attached!r}"
    )

    ghost = ctx.unique_name("sim2real-behav-fn-ghost-")
    code, message = _error(lambda: lam.get_function_code_signing_config(FunctionName=ghost))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a never-created function, got {code!r}: {message!r}"
    )
    expected_message = f"Function not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{ghost}"
    assert message == expected_message, (
        f"expected message {expected_message!r} for a never-created function, got {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
