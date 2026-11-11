"""code-signing-config-switched-to-enforce-refuses-the-next-unsigned-layer-attach."""

from __future__ import annotations

import io
import os
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "code-signing-config-switched-to-enforce-refuses-the-next-unsigned-layer-attach"
GROUP = "packaging"
SERVICES = ["lambda"]

_BASIC_EXEC_POLICY = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"


def _zip(code, filename="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, code)
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


def _wait_settled(ctx, lam, fn, timeout_s=120):
    """Poll until the function is Active with no update in flight."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=fn)
        if last["State"] == "Failed":
            raise AssertionError(f"{fn} entered State=Failed: {last.get('StateReason')}")
        if last.get("LastUpdateStatus") == "Failed":
            return last
        if last["State"] == "Active" and last.get("LastUpdateStatus") in (None, "Successful"):
            return last
        time.sleep(2)
    raise TimeoutError(f"{fn} did not settle within {timeout_s:.0f}s; last={last!r}")


def _client_error(call):
    """(code, message) of a call that MUST fail; raises if it unexpectedly succeeds."""
    try:
        call()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(
        "the call was expected to be refused but it SUCCEEDED — an unsigned layer was accepted "
        "under an Enforce code-signing policy"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateCodeSigningConfig switching an attached config from Warn to Enforce governs the next
    deploy: the unsigned layer the Warn policy let through is then refused with
    CodeVerificationFailedException and the function's Layers stay empty.

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

    # A CodeSigningConfig needs at least one Signer profile VERSION arn in AllowedPublishers.
    # Nothing is ever signed here: the layer is never run through AWS Signer, so it is unsigned
    # on every attach attempt regardless of mode.
    profile_name = "sim2real_behav_lcsp_" + os.urandom(5).hex()
    profile = signer.put_signing_profile(
        profileName=profile_name, platformId="AWSLambda-SHA384-ECDSA",
        tags={"sim2real:managed": "true"},
    )
    # A signing profile cannot be hard-deleted; Cancel is the documented teardown.
    ctx.on_cleanup(lambda: signer.cancel_signing_profile(profileName=profile_name))

    csc_arn = lam.create_code_signing_config(
        Description="sim2real-behav layer code signing",
        AllowedPublishers={"SigningProfileVersionArns": [profile["profileVersionArn"]]},
        CodeSigningPolicies={"UntrustedArtifactOnDeployment": "Warn"},
        Tags={"sim2real:managed": "true"},
    )["CodeSigningConfig"]["CodeSigningConfigArn"]
    # Registered before the function below, so LIFO tears the function down FIRST: a
    # CodeSigningConfig still attached to a function cannot be deleted.
    ctx.on_cleanup(lambda: lam.delete_code_signing_config(CodeSigningConfigArn=csc_arn))

    layer_name = ctx.unique_name("sim2real-behav-layer-")
    layer = lam.publish_layer_version(
        LayerName=layer_name, Content={"ZipFile": _zip("unused", "python/unused.py")},
        CompatibleRuntimes=["python3.12"],
    )
    layer_arn = layer["LayerVersionArn"]
    ctx.on_cleanup(lambda: lam.delete_layer_version(LayerName=layer_name,
                                                    VersionNumber=layer["Version"]))

    fn_name = ctx.unique_name("sim2real-behav-csfn-")
    _create_function(
        ctx, lam, FunctionName=fn_name, Runtime="python3.12", Handler="index.handler",
        Role=role_arn, Code={"ZipFile": _zip("def handler(event, context): return 'v1'\n")},
        MemorySize=128, Timeout=30, Tags={"sim2real:managed": "true"},
        CodeSigningConfigArn=csc_arn,
    )
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, fn_name))
    _wait_settled(ctx, lam, fn_name)

    # ---- positive control: under Warn, attaching the unsigned layer succeeds ----
    lam.update_function_configuration(FunctionName=fn_name, Layers=[layer_arn])
    warn_cfg = _wait_settled(ctx, lam, fn_name)
    assert warn_cfg["LastUpdateStatus"] == "Successful", (
        f"attaching the unsigned layer under Warn did not succeed: "
        f"{warn_cfg.get('LastUpdateStatus')!r} {warn_cfg.get('LastUpdateStatusReason')!r}"
    )
    assert [l["Arn"] for l in warn_cfg.get("Layers", [])] == [layer_arn], (
        f"the Warn attach left Layers={warn_cfg.get('Layers')!r}, expected only {layer_arn!r}"
    )

    # ---- detach it, then switch the SAME config to Enforce ----
    lam.update_function_configuration(FunctionName=fn_name, Layers=[])
    detached_cfg = _wait_settled(ctx, lam, fn_name)
    assert detached_cfg.get("Layers", []) == [], (
        f"removing the layer left Layers={detached_cfg.get('Layers')!r}"
    )
    lam.update_code_signing_config(
        CodeSigningConfigArn=csc_arn,
        CodeSigningPolicies={"UntrustedArtifactOnDeployment": "Enforce"},
    )

    # ---- break exactly one thing: re-attach the IDENTICAL unsigned layer under Enforce ----
    code, message = _client_error(
        lambda: lam.update_function_configuration(FunctionName=fn_name, Layers=[layer_arn])
    )
    assert code == "CodeVerificationFailedException", (
        f"re-attaching the unsigned layer under Enforce was refused with {code!r}, not "
        f"CodeVerificationFailedException: {message}"
    )
    expected_message = (
        "Lambda cannot deploy the function. The function or layer might be signed using a "
        f"signature that the client is not configured to accept. Check the provided signature "
        f"for {layer_arn}."
    )
    assert message == expected_message, (
        f"the Enforce refusal carried message {message!r}, expected {expected_message!r}"
    )

    # ---- the effect is absent: the function still has no layers ----
    after = _wait_settled(ctx, lam, fn_name)
    assert after.get("Layers", []) == [], (
        f"the refused layer attach left Layers={after.get('Layers')!r} instead of []"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
