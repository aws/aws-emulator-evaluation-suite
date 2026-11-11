"""update-function-configuration-signature-errors."""

from __future__ import annotations

import io
import json
import os
import textwrap
import time
import uuid
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "update-function-configuration-signature-errors"
GROUP = 'code_signing'
SERVICES = ['lambda']

HANDLER_V1 = "def handler(event, context): return {'marker': 'v1', 'echo': event}"


def _make_zip(code, filename="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


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


def _wait_settled(lam, fn, timeout_s=90):
    """Poll until the function is Active and its last configuration update has finished."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=fn)
        if last["State"] == "Failed":
            raise AssertionError(f"Function {fn} entered Failed: {last.get('StateReason')}")
        if last.get("LastUpdateStatus") == "Failed":
            raise AssertionError(f"{fn} LastUpdateStatus Failed: {last.get('LastUpdateStatusReason')}")
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

    Raises rather than returning a falsy sentinel.
    """
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        "the call was expected to be refused but it SUCCEEDED — an unsigned layer was accepted "
        "under an Enforce code-signing policy"
    )


def _publish_layer(ctx, lam):
    layer_name = ctx.unique_name("sim2real-behav-layer-")
    value = f"sim2real-{uuid.uuid4().hex[:12]}"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("python/sim2real_marker_module.py", f"VALUE = {value!r}\n")
    resp = lam.publish_layer_version(
        LayerName=layer_name, Content={"ZipFile": buf.getvalue()},
        CompatibleRuntimes=["python3.12"],
    )
    ctx.on_cleanup(lambda: lam.delete_layer_version(LayerName=layer_name, VersionNumber=resp["Version"]))
    return resp["LayerVersionArn"]


def _create_code_signing_config(ctx, lam, profile_version_arn, *, enforce):
    resp = lam.create_code_signing_config(
        AllowedPublishers={"SigningProfileVersionArns": [profile_version_arn]},
        CodeSigningPolicies={"UntrustedArtifactOnDeployment": "Enforce" if enforce else "Warn"},
        Description="sim2real-behav test csc",
    )
    arn = resp["CodeSigningConfig"]["CodeSigningConfigArn"]
    # Registered here, before the functions below are created, so LIFO tears the functions down
    # FIRST: a CodeSigningConfig still attached to a function cannot be deleted.
    ctx.on_cleanup(lambda: lam.delete_code_signing_config(CodeSigningConfigArn=arn))
    return arn


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Attaching an unsigned layer via UpdateFunctionConfiguration under an Enforce
    CodeSigningConfig is CodeVerificationFailedException and attaches nothing, while the identical
    attach under a Warn config succeeds, so the refusal is the Enforce policy itself.
    """
    lam = ctx.client("lambda")
    signer = ctx.client("signer")

    # A CodeSigningConfig needs a real Signer profile version arn in AllowedPublishers. Nothing is
    # ever signed here: the negative and the Warn control both attach the layer unsigned.
    profile_name = "sim2real_behav_csp_" + os.urandom(5).hex()
    profile = signer.put_signing_profile(
        profileName=profile_name, platformId="AWSLambda-SHA384-ECDSA"
    )
    # A signing profile cannot be hard-deleted; Cancel is the documented teardown.
    ctx.on_cleanup(lambda: signer.cancel_signing_profile(profileName=profile_name))
    profile_version_arn = profile["profileVersionArn"]

    enforce_arn = _create_code_signing_config(ctx, lam, profile_version_arn, enforce=True)
    warn_arn = _create_code_signing_config(ctx, lam, profile_version_arn, enforce=False)

    enforce_fn = _deploy_function(ctx, lam, HANDLER_V1)
    warn_fn = _deploy_function(ctx, lam, HANDLER_V1)
    lam.put_function_code_signing_config(CodeSigningConfigArn=enforce_arn, FunctionName=enforce_fn)
    lam.put_function_code_signing_config(CodeSigningConfigArn=warn_arn, FunctionName=warn_fn)

    layer_arn = _publish_layer(ctx, lam)

    code, message = _error(
        lambda: lam.update_function_configuration(FunctionName=enforce_fn, Layers=[layer_arn])
    )
    assert code == "CodeVerificationFailedException", (
        f"expected CodeVerificationFailedException for an unsigned layer under Enforce, got {code}"
    )
    expected_message = (
        "Lambda cannot deploy the function. The function or layer might be signed using a "
        "signature that the client is not configured to accept. Check the provided signature "
        f"for {layer_arn}."
    )
    assert message == expected_message, (
        f"expected the exact CodeVerificationFailedException message {expected_message!r}, got {message!r}"
    )

    cfg = lam.get_function_configuration(FunctionName=enforce_fn)
    assert not cfg.get("Layers"), (
        f"a rejected UpdateFunctionConfiguration must not attach the layer, got {cfg.get('Layers')}"
    )

    lam.update_function_configuration(FunctionName=warn_fn, Layers=[layer_arn])
    warn_cfg = _wait_settled(lam, warn_fn)
    warn_layer_arns = [layer["Arn"] for layer in warn_cfg.get("Layers", [])]
    assert layer_arn in warn_layer_arns, (
        f"the Warn function did not accept the identical unsigned layer, so the Enforce refusal "
        f"cannot be attributed to the policy: {warn_layer_arns!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
