"""create-function-with-container-image-rejects-code-signing-config."""

from __future__ import annotations

import io
import os
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "create-function-with-container-image-rejects-code-signing-config"
GROUP = "packaging"
SERVICES = ["lambda"]

_BASIC_EXEC_POLICY = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"


def _zip(code):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _budget_s(ctx, cap_s: float) -> float:
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _create_function(ctx, lam, **kwargs):
    """CreateFunction, retrying only while a freshly created role is not yet assumable."""
    timeout_s = _budget_s(ctx, 90)
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response["Error"]
            propagating = (err["Code"] == "InvalidParameterValueException"
                           and "cannot be assumed" in err.get("Message", ""))
            if not propagating:
                raise
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    f"the execution role was not assumable within {timeout_s:.0f}s: {err!r}"
                ) from exc
            time.sleep(3)


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


def _client_error(call):
    """(code, message) of a call that MUST fail; raises if it unexpectedly succeeds."""
    try:
        call()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(
        "the call was expected to be refused but it SUCCEEDED — a container-image CreateFunction "
        "accepted a CodeSigningConfigArn"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A zip-packaged function accepts a CodeSigningConfigArn at creation, but the identical config
    on an otherwise-equivalent container-image CreateFunction is refused with
    InvalidParameterValueException: code signing applies only to zip-packaged functions.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/configuration-codesigning.html
    """
    lam = ctx.client("lambda")
    iam = ctx.client("iam")
    signer = ctx.client("signer")

    role_name = ctx.unique_name("sim2real-behav-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
                                 '"Principal":{"Service":"lambda.amazonaws.com"},'
                                 '"Action":"sts:AssumeRole"}]}',
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_BASIC_EXEC_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_BASIC_EXEC_POLICY))

    # Nothing is ever signed here: an unsigned zip under a Warn config is accepted regardless, so
    # the positive control only needs CreateFunction to accept the CodeSigningConfigArn at all.
    profile_name = "sim2real_behav_icsp_" + os.urandom(5).hex()
    profile = signer.put_signing_profile(
        profileName=profile_name, platformId="AWSLambda-SHA384-ECDSA",
        tags={"sim2real:managed": "true"},
    )
    ctx.on_cleanup(lambda: signer.cancel_signing_profile(profileName=profile_name))
    csc_arn = lam.create_code_signing_config(
        Description="sim2real-behav image code signing",
        AllowedPublishers={"SigningProfileVersionArns": [profile["profileVersionArn"]]},
        CodeSigningPolicies={"UntrustedArtifactOnDeployment": "Warn"},
        Tags={"sim2real:managed": "true"},
    )["CodeSigningConfig"]["CodeSigningConfigArn"]
    ctx.on_cleanup(lambda: lam.delete_code_signing_config(CodeSigningConfigArn=csc_arn))

    # ---- positive control: a zip-packaged function accepts the config at creation ----
    zip_fn_name = ctx.unique_name("sim2real-behav-zipfn-")
    created = _create_function(
        ctx, lam, FunctionName=zip_fn_name, Runtime="python3.12", Handler="index.handler",
        Role=role_arn, Code={"ZipFile": _zip("def handler(event, context): return 'v1'\n")},
        MemorySize=128, Timeout=30, Tags={"sim2real:managed": "true"},
        CodeSigningConfigArn=csc_arn,
    )
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, zip_fn_name))
    assert created["PackageType"] == "Zip", f"unexpected PackageType {created['PackageType']!r}"
    attached = lam.get_function_code_signing_config(FunctionName=zip_fn_name)["CodeSigningConfigArn"]
    assert attached == csc_arn, f"the zip function's attached config is {attached!r}, not {csc_arn!r}"

    # ---- break exactly one thing: the SAME config on an otherwise-equivalent image function ----
    image_fn_name = ctx.unique_name("sim2real-behav-imgfn-")
    image_uri = f"{ctx.account}.dkr.ecr.{ctx.region}.amazonaws.com/sim2real-behav-nonexistent:latest"

    # Registered before the call, so a target that wrongly accepts it still tears it down.
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, image_fn_name))

    def _create_image_with_csc():
        _create_function(
            ctx, lam, FunctionName=image_fn_name, PackageType="Image",
            Code={"ImageUri": image_uri}, Role=role_arn,
            Tags={"sim2real:managed": "true"}, CodeSigningConfigArn=csc_arn,
        )

    code, message = _client_error(_create_image_with_csc)
    assert code == "InvalidParameterValueException", (
        f"a container-image CreateFunction naming a CodeSigningConfigArn was refused with "
        f"{code!r}, not InvalidParameterValueException: {message}"
    )
    assert message == "Code signing is not supported for functions created with container images.", (
        f"unexpected refusal message: {message!r}"
    )

    # ---- the effect is absent: no image function was created ----
    found = _client_error(lambda: lam.get_function(FunctionName=image_fn_name))
    assert found[0] == "ResourceNotFoundException", (
        f"GetFunction for the refused image function returned {found!r}, expected "
        f"ResourceNotFoundException"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
