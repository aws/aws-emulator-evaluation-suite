"""code-signing-enforce-rejects-unsigned-package-rejected."""

from __future__ import annotations

import io
import json
import os
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "code-signing-enforce-rejects-unsigned-package-rejected"
GROUP = 'packaging'
SERVICES = ['lambda']

V1 = "def handler(event, context): return 'v1'\n"
V2 = "def handler(event, context): return 'v2'\n"


def _make_zip(code, filename="index.py"):
    """A deterministic package: a fixed entry timestamp makes the same code the same bytes."""
    buf = io.BytesIO()
    info = zipfile.ZipInfo(filename, date_time=(2020, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o644 << 16
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(info, textwrap.dedent(code))
    return buf.getvalue()


_BASIC_EXEC_POLICY = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
_ROLES: dict = {}


def _role_arn(ctx):
    """Create this check's own Lambda execution role once per run and register its cleanup."""
    import json as _json

    held = _ROLES.get(id(ctx))
    if held is not None and held[0] is ctx:
        return held[1]
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_BASIC_EXEC_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_BASIC_EXEC_POLICY))
    _ROLES[id(ctx)] = (ctx, arn)
    return arn


def _create_function(lam, **kwargs):
    """CreateFunction, retrying only while a freshly created role is not yet assumable."""
    from botocore.exceptions import ClientError as _ClientError

    deadline = time.monotonic() + 90
    while True:
        try:
            return lam.create_function(**kwargs)
        except _ClientError as exc:
            err = exc.response.get("Error", {})
            propagating = err.get("Code") == "InvalidParameterValueException" and "cannot be assumed" in err.get("Message", "")
            if not propagating or time.monotonic() >= deadline:
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


def _poll(probe, timeout_s, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        got = probe()
        if got:
            return got
        time.sleep(interval_s)
    return None


def _wait_settled(lam, fn, timeout_s=180):
    """Poll until the function is Active and no update is in flight."""
    def _probe():
        cfg = lam.get_function_configuration(FunctionName=fn)
        if cfg["State"] == "Failed":
            raise AssertionError(f"{fn} entered State=Failed: {cfg.get('StateReason')}")
        if cfg.get("LastUpdateStatus") == "Failed":
            return cfg
        if cfg["State"] == "Active" and cfg.get("LastUpdateStatus") in (None, "Successful"):
            return cfg
        return None

    cfg = _poll(_probe, timeout_s)
    assert cfg is not None, f"{fn} did not settle within {timeout_s}s"
    return cfg


def _client_error(call):
    """The AWS error (code, message) for a call that MUST fail.

    A call that unexpectedly SUCCEEDS raises rather than returning a sentinel, so wrongly accepted
    input is not disguised as an error-code mismatch.
    """
    try:
        call()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        "the call was expected to be refused but it SUCCEEDED — an unsigned deployment package "
        "was accepted under an Enforce code-signing policy"
    )


def _invoke_body(lam, fn):
    resp = lam.invoke(FunctionName=fn, Payload=b"{}")
    raw = resp["Payload"].read()
    assert resp["StatusCode"] == 200, f"{fn}: StatusCode {resp['StatusCode']!r} {raw!r}"
    assert "FunctionError" not in resp, (
        f"{fn} failed with FunctionError={resp.get('FunctionError')!r}: {raw!r}"
    )
    return json.loads(raw)


def _deploy_unsigned(ctx, lam, code):
    """Create a function from an UNSIGNED zip with no code-signing config attached yet.

    AWS refuses CreateFunction with CodeVerificationFailedException when an Enforce config comes
    with an unsigned zip, so the config is attached afterwards via PutFunctionCodeSigningConfig.
    """
    name = ctx.unique_name("sim2real-behav-csfn-")
    _create_function(lam, 
        FunctionName=name, Runtime="python3.12", Handler="index.handler",
        Role=_role_arn(ctx), Code={"ZipFile": _make_zip(code)},
        MemorySize=128, Timeout=30, Tags={"sim2real:managed": "true"},
    )
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, name))
    return name


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:control", "plane:data")
def run(ctx) -> None:
    """Under Enforce, UpdateFunctionCode with an unsigned zip fails with CodeVerificationFailedException
    and invoke still runs the old code; under Warn the same zip is accepted and goes live.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/configuration-codesigning.html
    """
    lam = ctx.client("lambda")
    signer = ctx.client("signer")

    # A CodeSigningConfig needs at least one Signer profile VERSION arn in AllowedPublishers.
    # Nothing is ever signed here: the negative and the Warn control both work unsigned.
    profile_name = "sim2real_behav_csp_" + os.urandom(5).hex()
    profile = signer.put_signing_profile(
        profileName=profile_name, platformId="AWSLambda-SHA384-ECDSA",
        tags={"sim2real:managed": "true"},
    )
    # A signing profile cannot be hard-deleted; Cancel is the documented teardown and it is what
    # takes it out of the active set.
    ctx.on_cleanup(lambda: signer.cancel_signing_profile(profileName=profile_name))
    profile_version_arn = profile["profileVersionArn"]

    def _csc(mode):
        created = lam.create_code_signing_config(
            Description=f"sim2real-behav code signing {mode}",
            AllowedPublishers={"SigningProfileVersionArns": [profile_version_arn]},
            CodeSigningPolicies={"UntrustedArtifactOnDeployment": mode},
            Tags={"sim2real:managed": "true"},
        )["CodeSigningConfig"]
        arn = created["CodeSigningConfigArn"]
        # Registered HERE, before the functions below are created, so LIFO tears the functions down
        # FIRST: a CodeSigningConfig that is still attached to a function cannot be deleted.
        ctx.on_cleanup(lambda: lam.delete_code_signing_config(CodeSigningConfigArn=arn))
        assert created["CodeSigningPolicies"]["UntrustedArtifactOnDeployment"] == mode, (
            f"the policy mode did not round-trip: {created!r}"
        )
        return arn

    enforce_arn = _csc("Enforce")
    warn_arn = _csc("Warn")

    enforce_fn = _deploy_unsigned(ctx, lam, V1)
    warn_fn = _deploy_unsigned(ctx, lam, V1)
    _wait_settled(lam, enforce_fn)
    _wait_settled(lam, warn_fn)

    lam.put_function_code_signing_config(
        CodeSigningConfigArn=enforce_arn, FunctionName=enforce_fn
    )
    lam.put_function_code_signing_config(
        CodeSigningConfigArn=warn_arn, FunctionName=warn_fn
    )
    assert lam.get_function_code_signing_config(
        FunctionName=enforce_fn
    )["CodeSigningConfigArn"] == enforce_arn, "the Enforce config did not attach"
    assert lam.get_function_code_signing_config(
        FunctionName=warn_fn
    )["CodeSigningConfigArn"] == warn_arn, "the Warn config did not attach"

    enforce_cfg = _wait_settled(lam, enforce_fn)
    v1_sha = enforce_cfg["CodeSha256"]
    enforce_fn_arn = enforce_cfg["FunctionArn"]
    assert _invoke_body(lam, enforce_fn) == "v1", "the Enforce function is not running v1 yet"

    # ---- break exactly one thing: push the unsigned v2 zip under Enforce ----
    code, message = _client_error(
        lambda: lam.update_function_code(FunctionName=enforce_fn, ZipFile=_make_zip(V2))
    )
    assert code == "CodeVerificationFailedException", (
        f"an unsigned deployment package under UntrustedArtifactOnDeployment=Enforce was refused "
        f"with {code!r}, not CodeVerificationFailedException"
    )
    expected_message = (
        "Lambda cannot deploy the function. The function or layer might be signed using a signature "
        f"that the client is not configured to accept. Check the provided signature for {enforce_fn_arn}."
    )
    assert message == expected_message, (
        f"the Enforce refusal carried message {message!r}, expected {expected_message!r}"
    )

    # ---- the effect is absent: the code did not change and the OLD code still runs ----
    after = _wait_settled(lam, enforce_fn)
    assert after["CodeSha256"] == v1_sha, (
        f"CodeSha256 changed from {v1_sha!r} to {after['CodeSha256']!r} despite the refusal — the "
        f"rejected package was stored anyway"
    )
    assert _invoke_body(lam, enforce_fn) == "v1", (
        "the Enforce function is executing the code whose deployment was refused"
    )

    # ---- positive control: the SAME unsigned zip under Warn is accepted and goes live ----
    warn_v1_sha = _wait_settled(lam, warn_fn)["CodeSha256"]
    assert warn_v1_sha == v1_sha, (
        f"the two functions did not start from the same package: {warn_v1_sha!r} vs {v1_sha!r}"
    )
    lam.update_function_code(FunctionName=warn_fn, ZipFile=_make_zip(V2))
    warn_after = _wait_settled(lam, warn_fn)
    assert warn_after["LastUpdateStatus"] == "Successful", (
        f"the Warn function's update did not succeed: {warn_after.get('LastUpdateStatus')!r} "
        f"{warn_after.get('LastUpdateStatusReason')!r}"
    )
    assert warn_after["CodeSha256"] != v1_sha, (
        f"the Warn function's CodeSha256 did not change: {warn_after['CodeSha256']!r}"
    )
    assert _invoke_body(lam, warn_fn) == "v2", (
        "the Warn function did not run the unsigned code it accepted, so the Enforce refusal "
        "cannot be attributed to the policy"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
