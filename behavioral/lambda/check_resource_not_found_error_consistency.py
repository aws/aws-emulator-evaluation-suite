"""resource-not-found-error-consistency."""

from __future__ import annotations

import io
import json
import textwrap
import time
import uuid
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "resource-not-found-error-consistency"
GROUP = 'errors'
SERVICES = ['lambda']

HANDLER_V1 = "def handler(event, context): return {'marker': 'v1', 'echo': event}"


def _make_zip(code, filename="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


_ROLES: dict = {}
_BASIC_EXEC = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"


def _exec_role_arn(ctx):
    """An execution role this check creates (once per run) and deletes in cleanup."""
    if id(ctx) in _ROLES:
        return _ROLES[id(ctx)]
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-lambda-exec-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.attach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC))
    _ROLES[id(ctx)] = arn
    return arn


def _create_function_retrying(lam, **kwargs):
    """CreateFunction, retried while the role this check just created propagates in IAM."""
    deadline = time.monotonic() + 90
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            if "cannot be assumed" in str(exc) and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise


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


def _delete_alias_ignore(lam, fn, name):
    try:
        lam.delete_alias(FunctionName=fn, Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_layer_ignore(lam, name, version):
    try:
        lam.delete_layer_version(LayerName=name, VersionNumber=version)
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


def _deploy_function(ctx, lam, code, *, name=None):
    name = name or ctx.unique_name("sim2real-behav-fn-")
    _create_function_retrying(
        lam,
        FunctionName=name,
        Runtime="python3.12",
        Handler="index.handler",
        Role=_exec_role_arn(ctx),
        Code={"ZipFile": _make_zip(code)},
        MemorySize=128,
        Timeout=30,
    )
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, name))
    _wait_active(lam, name)
    return name


def _error(fn):
    """Call fn() and return its (error code, message); an unexpected success raises so it is not
    hidden behind a vague code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected ResourceNotFoundException, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Get* on a nonexistent function, alias, layer, ESM or capacity provider returns
    ResourceNotFoundException with the exact message, not an empty or default payload.
    """
    lam = ctx.client("lambda")
    missing_fn = ctx.unique_name("sim2real-behav-fn-missing-")
    fn_code, fn_msg = _error(lambda: lam.get_function(FunctionName=missing_fn))
    assert fn_code == "ResourceNotFoundException", f"GetFunction: expected ResourceNotFoundException, got {fn_code}"
    expected = f"Function not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{missing_fn}"
    assert fn_msg == expected, f"GetFunction: expected message {expected!r}, got {fn_msg!r}"

    fn = _deploy_function(ctx, lam, HANDLER_V1)

    # Positive control: GetFunction on the function this check just created must succeed.
    got_fn = lam.get_function(FunctionName=fn)
    assert got_fn["Configuration"]["FunctionName"] == fn, got_fn

    v1 = lam.publish_version(FunctionName=fn)["Version"]
    alias_name = ctx.unique_name("alias-present-")
    lam.create_alias(FunctionName=fn, Name=alias_name, FunctionVersion=v1)
    ctx.on_cleanup(lambda: _delete_alias_ignore(lam, fn, alias_name))

    # Positive control: GetAlias on the alias this check just created must succeed.
    got_alias = lam.get_alias(FunctionName=fn, Name=alias_name)
    assert got_alias["FunctionVersion"] == v1, got_alias

    alias_missing = ctx.unique_name("alias-missing-")
    alias_code, alias_msg = _error(lambda: lam.get_alias(FunctionName=fn, Name=alias_missing))
    assert alias_code == "ResourceNotFoundException", (
        f"GetAlias: expected ResourceNotFoundException, got {alias_code}"
    )
    expected = (
        f"Cannot find alias arn: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{fn}:{alias_missing}"
    )
    assert alias_msg == expected, f"GetAlias: expected message {expected!r}, got {alias_msg!r}"

    layer_name = ctx.unique_name("sim2real-behav-layer-")
    layer = lam.publish_layer_version(
        LayerName=layer_name,
        Content={"ZipFile": _make_zip("LAYER = 1\n", "python/sim2real_layer.py")},
        CompatibleRuntimes=["python3.12"],
    )
    ctx.on_cleanup(lambda: _delete_layer_ignore(lam, layer_name, layer["Version"]))

    # Positive control: GetLayerVersion on the layer this check just created must succeed.
    got_layer = lam.get_layer_version(LayerName=layer_name, VersionNumber=layer["Version"])
    assert got_layer["LayerArn"] is not None, got_layer

    layer_missing = ctx.unique_name("layer-missing-")
    layer_code, layer_msg = _error(
        lambda: lam.get_layer_version(LayerName=layer_missing, VersionNumber=1)
    )
    assert layer_code == "ResourceNotFoundException", (
        f"GetLayerVersion: expected ResourceNotFoundException, got {layer_code}"
    )
    expected = "The resource you requested does not exist."
    assert layer_msg == expected, f"GetLayerVersion: expected message {expected!r}, got {layer_msg!r}"

    # ESM and capacity provider are negative-only: their setup is costly and covered elsewhere.
    esm_uuid = str(uuid.uuid4())
    esm_code, esm_msg = _error(lambda: lam.get_event_source_mapping(UUID=esm_uuid))
    assert esm_code == "ResourceNotFoundException", (
        f"GetEventSourceMapping: expected ResourceNotFoundException, got {esm_code}"
    )
    expected = "The resource you requested does not exist."
    assert esm_msg == expected, f"GetEventSourceMapping: expected message {expected!r}, got {esm_msg!r}"

    cp_missing = ctx.unique_name("cp-missing-")
    cp_code, cp_msg = _error(lambda: lam.get_capacity_provider(CapacityProviderName=cp_missing))
    assert cp_code == "ResourceNotFoundException", (
        f"GetCapacityProvider: expected ResourceNotFoundException, got {cp_code}"
    )
    expected = (
        f"Capacity provider not found: arn:aws:lambda:{ctx.region}:{ctx.account}:capacity-provider:"
        f"{cp_missing}. Check that the ARN is correct and the capacity provider exists in this Region."
    )
    assert cp_msg == expected, f"GetCapacityProvider: expected message {expected!r}, got {cp_msg!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
