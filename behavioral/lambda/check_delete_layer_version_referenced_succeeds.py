"""delete-layer-version-referenced-succeeds."""

from __future__ import annotations

import io
import json
import textwrap
import time
import uuid
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "delete-layer-version-referenced-succeeds"
GROUP = 'layers'
SERVICES = ['lambda']

HANDLER_V1 = "def handler(event, context): return {'marker': 'v1', 'echo': event}"


def _make_zip(code, filename="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


_ROLE_ARNS: dict = {}


def _role_arn(ctx):
    key = id(ctx)
    if key not in _ROLE_ARNS:
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
        _ROLE_ARNS[key] = role["Role"]["Arn"]
    return _ROLE_ARNS[key]


def _create_function(lam, kwargs, timeout_s=60):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if (
                err.get("Code") == "InvalidParameterValueException"
                and "cannot be assumed" in err.get("Message", "")
                and time.monotonic() < deadline
            ):
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


def _deploy_function(ctx, lam, code, *, name=None, layers=None):
    name = name or ctx.unique_name("sim2real-behav-fn-")
    kwargs = {
        "FunctionName": name,
        "Runtime": "python3.12",
        "Handler": "index.handler",
        "Role": _role_arn(ctx),
        "Code": {"ZipFile": _make_zip(code)},
        "MemorySize": 128,
        "Timeout": 30,
    }
    if layers:
        kwargs["Layers"] = layers
    _create_function(lam, kwargs)
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, name))
    _wait_active(lam, name)
    return name


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
    version = resp["Version"]
    ctx.on_cleanup(lambda: lam.delete_layer_version(LayerName=layer_name, VersionNumber=version))
    return layer_name, version, resp["LayerVersionArn"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """DeleteLayerVersion succeeds while a function references the version and drops it from the
    listing, and the function keeps the layer and still invokes with its code (AWS keeps a copy until
    no function refers to it)."""
    lam = ctx.client("lambda")
    layer_name, version, layer_arn = _publish_layer(ctx, lam)
    fn = _deploy_function(ctx, lam, HANDLER_V1, layers=[layer_arn])

    cfg = lam.get_function_configuration(FunctionName=fn)
    assert layer_arn in [layer.get("Arn") for layer in cfg.get("Layers", [])], cfg

    lam.delete_layer_version(LayerName=layer_name, VersionNumber=version)

    listed = lam.list_layer_versions(LayerName=layer_name).get("LayerVersions", [])
    assert not any(v["Version"] == version for v in listed), (
        f"expected version {version} gone from ListLayerVersions after delete, got {listed}"
    )

    still_cfg = lam.get_function_configuration(FunctionName=fn)
    assert layer_arn in [layer.get("Arn") for layer in still_cfg.get("Layers", [])], (
        f"expected the referencing function's config to still show the (deleted) layer version, "
        f"got {still_cfg.get('Layers')}"
    )

    resp = lam.invoke(FunctionName=fn, Payload=json.dumps({"mode": "plain"}).encode("utf-8"))
    assert resp["StatusCode"] == 200, resp
    decoded = json.loads(resp["Payload"].read())
    assert decoded and decoded.get("marker") == "v1", decoded


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
