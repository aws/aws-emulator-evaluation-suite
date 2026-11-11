"""create-function-code-validation-errors."""

from __future__ import annotations

import io
import json
import textwrap
import time
import uuid
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "create-function-code-validation-errors"
GROUP = 'code_signing'
SERVICES = ['lambda']

HANDLER_V1 = "def handler(event, context): return {'marker': 'v1', 'echo': event}"


def _make_zip(code, filename="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


_LAMBDA_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})
_BASIC_EXEC_POLICY = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
_ROLE_NOT_ASSUMABLE = "The role defined for the function cannot be assumed by Lambda."
_ROLES = []


def _delete_role(iam, name):
    for call in (
        lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC_POLICY),
        lambda: iam.delete_role(RoleName=name),
    ):
        try:
            call()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
                raise


def _execution_role(ctx):
    """The execution role this check creates for its functions, one per run."""
    for owner, arn in _ROLES:
        if owner is ctx:
            return arn
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-lam-exec-")
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=_LAMBDA_TRUST)["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, name))
    iam.attach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC_POLICY)
    _ROLES.append((ctx, arn))
    return arn


def _call_create_function(lam, **kwargs):
    """CreateFunction, retried while IAM propagates the execution role this check created."""
    deadline = time.monotonic() + 90
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if (
                err.get("Code") != "InvalidParameterValueException"
                or err.get("Message") != _ROLE_NOT_ASSUMABLE
                or time.monotonic() > deadline
            ):
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


def _error_code(fn):
    """The AWS (error code, error message) for a call that MUST fail.

    A call that unexpectedly SUCCEEDS raises rather than returning a falsy sentinel: an
    over-permissive target accepting input real AWS rejects is the strongest signal available
    here, and returning None would disguise it as an error-code mismatch.
    """
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED: {result!r}")


def _create_code_signing_config(ctx, lam, *, enforce=True):
    """Create a real CodeSigningConfig whose only allowed signer is a syntactically-valid but
    non-existent AWS Signer profile version ARN. Lambda does not validate that the profile exists
    at CreateCodeSigningConfig time, so this reliably produces a CSC that NO deployment package can
    ever satisfy — making any subsequent unsigned-code deployment against it deterministically fail
    signature validation under an Enforce policy. Return the CSC's ARN.
    """
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
    """CreateFunction with a nonexistent CodeSigningConfigArn is CodeSigningConfigNotFoundException and
    with unsigned code under an Enforce code signing config is CodeVerificationFailedException, both
    with exact messages, and neither function exists afterwards."""
    lam = ctx.client("lambda")
    account = _account(ctx)
    role_arn = _execution_role(ctx)
    fake_csc_arn = f"arn:aws:lambda:{ctx.region}:{account}:code-signing-config:csc-{uuid.uuid4().hex[:17]}"

    name1 = ctx.unique_name("sim2real-behav-fn-")
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, name1))  # guard cleanup if this unexpectedly succeeds
    code1, message1 = _error_code(
        lambda: _call_create_function(lam, 
            FunctionName=name1,
            Runtime="python3.12",
            Role=role_arn,
            Handler="index.handler",
            Code={"ZipFile": _make_zip(HANDLER_V1)},
            CodeSigningConfigArn=fake_csc_arn,
            Tags={"sim2real": "create-function-code-validation-errors"},
        )
    )
    assert code1 == "CodeSigningConfigNotFoundException", (
        f"expected CodeSigningConfigNotFoundException for a nonexistent CodeSigningConfigArn, got {code1}"
    )
    expected1 = (
        "The code signing configuration cannot be found. Check that the provided configuration "
        f"is not deleted: {fake_csc_arn}."
    )
    assert message1 == expected1, (
        f"a nonexistent CodeSigningConfigArn returned message {message1!r}, expected {expected1!r}"
    )
    still_gone1, gone_message1 = _error_code(lambda: lam.get_function(FunctionName=name1))
    assert still_gone1 == "ResourceNotFoundException", (
        f"a rejected CreateFunction must not leave a function behind, got {still_gone1}"
    )
    not_found1 = f"Function not found: arn:aws:lambda:{ctx.region}:{account}:function:{name1}"
    assert gone_message1 == not_found1, (
        f"GetFunction after the rejected create returned message {gone_message1!r}, "
        f"expected {not_found1!r}"
    )

    csc_arn = _create_code_signing_config(ctx, lam, enforce=True)
    name2 = ctx.unique_name("sim2real-behav-fn-")
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, name2))  # guard cleanup if this unexpectedly succeeds
    code2, message2 = _error_code(
        lambda: _call_create_function(lam, 
            FunctionName=name2,
            Runtime="python3.12",
            Role=role_arn,
            Handler="index.handler",
            Code={"ZipFile": _make_zip(HANDLER_V1)},
            CodeSigningConfigArn=csc_arn,
            Tags={"sim2real": "create-function-code-validation-errors"},
        )
    )
    assert code2 == "CodeVerificationFailedException", (
        f"expected CodeVerificationFailedException for unsigned code under an Enforce CSC, got {code2}"
    )
    expected2 = (
        "Lambda cannot deploy the function. The function or layer might be signed using a "
        "signature that the client is not configured to accept. Check the provided signature "
        f"for {name2}."
    )
    assert message2 == expected2, (
        f"unsigned code under an Enforce CSC returned message {message2!r}, expected {expected2!r}"
    )
    # independent read at the destination: the mutating call's own response is not the terminal
    # assertion — confirm the function was never created, mirroring the first leg.
    still_gone2, gone_message2 = _error_code(lambda: lam.get_function(FunctionName=name2))
    assert still_gone2 == "ResourceNotFoundException", (
        f"a rejected CreateFunction must not leave a function behind, got {still_gone2}"
    )
    not_found2 = f"Function not found: arn:aws:lambda:{ctx.region}:{account}:function:{name2}"
    assert gone_message2 == not_found2, (
        f"GetFunction after the rejected create returned message {gone_message2!r}, "
        f"expected {not_found2!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
