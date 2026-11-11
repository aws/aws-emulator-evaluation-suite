"""update-function-code-validation-errors."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import textwrap
import time
import uuid
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "update-function-code-validation-errors"
GROUP = 'code_signing'
SERVICES = ['lambda']

HANDLER_V1 = "def handler(event, context): return {'marker': 'v1', 'echo': event}"
HANDLER_V2 = "def handler(event, context): return {'marker': 'v2', 'echo': event}"
HANDLER_V3 = "def handler(event, context): return {'marker': 'v3', 'echo': event}"


def _make_zip(code, filename="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


def _code_sha256(zip_bytes):
    """Lambda's own recipe for CodeSha256: base64(sha256(deployment package))."""
    return base64.b64encode(hashlib.sha256(zip_bytes).digest()).decode()


_ROLES: dict = {}
_BASIC_EXEC = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
_ROLE_NOT_READY = "The role defined for the function cannot be assumed by Lambda."


def _role_arn(ctx):
    """Create this run's own Lambda execution role (once per run) and return its ARN."""
    if id(ctx) in _ROLES:
        return _ROLES[id(ctx)]
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.attach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC))
    _ROLES[id(ctx)] = arn
    return arn


def _create_function(lam, **kwargs):
    """CreateFunction, retried while a freshly created execution role is still propagating."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 90
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            not_ready = (err.get("Code") == "InvalidParameterValueException"
                         and err.get("Message") == _ROLE_NOT_READY)
            if not not_ready or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _account(ctx):
    return ctx.account


def _cleanup_fn(ctx, lam, name):
    try:
        lam.delete_function(FunctionName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{name}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_active(lam, fn, timeout_s=60):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=fn)
        if last["State"] == "Failed":
            raise AssertionError(f"Function {fn} entered Failed: {last.get('StateReason')}")
        if last["State"] == "Active":
            return
        time.sleep(1.0)
    raise AssertionError(f"{fn} Active not met within {timeout_s}s. Last: {last!r}")


def _wait_settled(lam, fn, timeout_s=120):
    """Poll until an in-flight UpdateFunctionCode has actually finished, not just been accepted."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=fn)
        if last["State"] == "Failed":
            raise AssertionError(f"{fn} entered State=Failed: {last.get('StateReason')}")
        if last.get("LastUpdateStatus") == "Failed":
            raise AssertionError(
                f"{fn} LastUpdateStatus=Failed: {last.get('LastUpdateStatusReason')}"
            )
        if last["State"] == "Active" and last.get("LastUpdateStatus") in (None, "Successful"):
            return last
        time.sleep(1.0)
    raise AssertionError(f"{fn} did not settle within {timeout_s}s. Last: {last!r}")


def _deploy_function(ctx, lam, code, *, name=None):
    name = name or ctx.unique_name("sim2real-behav-fn-")
    _create_function(
        lam,
        FunctionName=name,
        Runtime="python3.12",
        Handler="index.handler",
        Role=_role_arn(ctx),
        Code={"ZipFile": _make_zip(code)},
        MemorySize=128,
        Timeout=30,
    )
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, name))
    _wait_active(lam, name)
    return name


def _error(fn):
    """The AWS error (code, message) for a call that MUST fail.

    Raises on unexpected success rather than returning a falsy sentinel.
    """
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        "the call was expected to be refused but it SUCCEEDED — unsigned code was accepted "
        "under an Enforce code-signing policy"
    )


def _create_code_signing_config(ctx, lam, *, enforce=True):
    account = _account(ctx)
    fake_profile_arn = (
        f"arn:aws:signer:{ctx.region}:{account}:/signing-profiles/"
        f"sim2realbehav/{uuid.uuid4().hex[:16]}"
    )
    resp = lam.create_code_signing_config(
        AllowedPublishers={"SigningProfileVersionArns": [fake_profile_arn]},
        CodeSigningPolicies={"UntrustedArtifactOnDeployment": "Enforce" if enforce else "Warn"},
        Description="sim2real-behav test csc",
    )
    arn = resp["CodeSigningConfig"]["CodeSigningConfigArn"]
    ctx.on_cleanup(lambda: lam.delete_code_signing_config(CodeSigningConfigArn=arn))
    return arn


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateFunctionCode with unsigned code under an Enforce CodeSigningConfig is refused and
    stores nothing; the same update works before attach and after detach. Every leg checks
    CodeSha256 against base64(sha256(zip)), so a target storing different bytes fails.
    """
    lam = ctx.client("lambda")
    fn = _deploy_function(ctx, lam, HANDLER_V1)

    v2_zip = _make_zip(HANDLER_V2)
    lam.update_function_code(FunctionName=fn, ZipFile=v2_zip)
    settled = _wait_settled(lam, fn)
    expected_v2_sha = _code_sha256(v2_zip)
    assert settled["CodeSha256"] == expected_v2_sha, (
        f"positive control: after an unrestricted update CodeSha256 was "
        f"{settled['CodeSha256']!r}, expected {expected_v2_sha!r}"
    )
    before_sha = settled["CodeSha256"]

    csc_arn = _create_code_signing_config(ctx, lam, enforce=True)
    lam.put_function_code_signing_config(CodeSigningConfigArn=csc_arn, FunctionName=fn)
    assert lam.get_function_code_signing_config(FunctionName=fn)["CodeSigningConfigArn"] == csc_arn, (
        "the Enforce CodeSigningConfig did not attach"
    )

    v3_zip = _make_zip(HANDLER_V3)
    code, message = _error(lambda: lam.update_function_code(FunctionName=fn, ZipFile=v3_zip))
    assert code == "CodeVerificationFailedException", (
        f"an unsigned deployment package under UntrustedArtifactOnDeployment=Enforce was refused "
        f"with {code!r}, not CodeVerificationFailedException"
    )
    function_arn = lam.get_function_configuration(FunctionName=fn)["FunctionArn"]
    expected_message = (
        "Lambda cannot deploy the function. The function or layer might be signed using a "
        "signature that the client is not configured to accept. Check the provided signature "
        f"for {function_arn}."
    )
    assert message == expected_message, (
        f"expected the exact CodeVerificationFailedException message {expected_message!r}, got {message!r}"
    )

    after = lam.get_function_configuration(FunctionName=fn)
    assert after["CodeSha256"] == before_sha, (
        f"CodeSha256 changed from {before_sha!r} to {after['CodeSha256']!r} despite the refusal — "
        f"the rejected package was stored anyway"
    )

    # GetFunctionCodeSigningConfig with nothing attached returns 200 with no arn; it does not raise.
    lam.delete_function_code_signing_config(FunctionName=fn)
    detach_resp = lam.get_function_code_signing_config(FunctionName=fn)
    assert detach_resp.get("CodeSigningConfigArn") is None, (
        f"expected no CodeSigningConfig attached after DeleteFunctionCodeSigningConfig, still got "
        f"{detach_resp.get('CodeSigningConfigArn')!r}"
    )

    lam.update_function_code(FunctionName=fn, ZipFile=v3_zip)
    final = _wait_settled(lam, fn)
    expected_v3_sha = _code_sha256(v3_zip)
    assert final["CodeSha256"] == expected_v3_sha, (
        f"restore: after removing the CodeSigningConfig, the same update that was refused should "
        f"now succeed with CodeSha256 {expected_v3_sha!r}, got {final['CodeSha256']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
