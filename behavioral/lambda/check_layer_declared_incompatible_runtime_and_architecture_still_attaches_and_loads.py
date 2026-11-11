"""layer-declared-incompatible-runtime-and-architecture-still-attaches-and-loads."""

from __future__ import annotations

import io
import json
import time
import uuid
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "layer-declared-incompatible-runtime-and-architecture-still-attaches-and-loads"
GROUP = "layers_runtime"
SERVICES = ["lambda"]

_HANDLER = """\
def handler(event, context):
    import sim2real_l8_compat as mod

    return {"token": mod.stamp(), "file": mod.__file__}
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A layer whose CompatibleRuntimes and CompatibleArchitectures name neither the function's
    runtime nor its architecture still attaches on CreateFunction and UpdateFunctionConfiguration,
    and its content is extracted and imported at runtime.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/API_PublishLayerVersion.html
    """
    lam = ctx.client("lambda")
    iam = ctx.client("iam")
    token = uuid.uuid4().hex

    role_arn = _create_execution_role(ctx, iam)
    layer = _publish_layer(
        ctx, lam, ctx.unique_name("sim2real-behav-l8-compat-"),
        _zip({"python/sim2real_l8_compat.py": f'T = "{token}"\n\n\ndef stamp():\n    return T[::-1]\n'}),
        CompatibleRuntimes=["nodejs22.x"],
        CompatibleArchitectures=["arm64"],
    )
    got = lam.get_layer_version(LayerName=layer["LayerArn"], VersionNumber=layer["Version"])
    assert got["CompatibleRuntimes"] == ["nodejs22.x"], f"declared runtimes: {got['CompatibleRuntimes']!r}"
    assert got["CompatibleArchitectures"] == ["arm64"], (
        f"declared architectures: {got['CompatibleArchitectures']!r}"
    )

    created_fn = ctx.unique_name("sim2real-behav-l8-compatc-")
    _create_function(
        ctx, lam,
        FunctionName=created_fn, Runtime="python3.12", Architectures=["x86_64"], Role=role_arn,
        Handler="index.handler", Code={"ZipFile": _zip({"index.py": _HANDLER})},
        Layers=[layer["LayerVersionArn"]], Timeout=30, MemorySize=128, Tags={"sim2real": CHECK},
    )
    cfg = lam.get_function_configuration(FunctionName=created_fn)
    assert [ly["Arn"] for ly in cfg.get("Layers", [])] == [layer["LayerVersionArn"]], (
        f"CreateFunction must keep the incompatible layer attached; Layers={cfg.get('Layers')!r}"
    )
    out = _invoke_ok(lam, created_fn)
    assert out == {"token": token[::-1], "file": "/opt/python/sim2real_l8_compat.py"}, (
        f"the incompatible-declared layer must still be extracted and importable; got {out!r}"
    )

    updated_fn = ctx.unique_name("sim2real-behav-l8-compatu-")
    _create_function(
        ctx, lam,
        FunctionName=updated_fn, Runtime="python3.12", Architectures=["x86_64"], Role=role_arn,
        Handler="index.handler", Code={"ZipFile": _zip({"index.py": _HANDLER})},
        Timeout=30, MemorySize=128, Tags={"sim2real": CHECK},
    )
    error, body = _invoke(lam, updated_fn)
    assert error == "Unhandled" and body.get("errorType") == "ModuleNotFoundError", (
        f"without the layer the import must fail (control); FunctionError={error!r} {body!r}"
    )
    lam.update_function_configuration(FunctionName=updated_fn, Layers=[layer["LayerVersionArn"]])
    cfg = _wait_ready(lam, updated_fn)
    assert [ly["Arn"] for ly in cfg.get("Layers", [])] == [layer["LayerVersionArn"]], (
        f"UpdateFunctionConfiguration must attach the incompatible layer; Layers={cfg.get('Layers')!r}"
    )
    out = _invoke_ok(lam, updated_fn)
    assert out == {"token": token[::-1], "file": "/opt/python/sim2real_l8_compat.py"}, (
        f"after the update the layer's module must import; got {out!r}"
    )


# ===== helpers =====

def _make_zip(entries) -> bytes:
    """A zip from ``(name, content, mode)`` triples; ``mode`` carries the S_IF* type bits.

    The mode is written into ``external_attr`` with ``create_system=3`` (Unix), which is the only
    place a zip records file type and permission bits.
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content, mode in entries:
            info = zipfile.ZipInfo(name, date_time=(2024, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = mode << 16
            data = content.encode() if isinstance(content, str) else content
            zf.writestr(info, data)
    return buf.getvalue()


def _zip(files: dict) -> bytes:
    return _make_zip([(name, content, 0o100644) for name, content in files.items()])


def _error(fn) -> tuple[str, str]:
    """``(code, message)`` of the ClientError ``fn`` raises. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {str(result)[:400]}")


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` means gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _create_execution_role(ctx, iam) -> str:
    """This check's own execution role — nothing pre-existing in the account is assumed."""
    role_name = ctx.unique_name("sim2real-behav-l8-role-")
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(
        _teardown(
            lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn), "NoSuchEntity"
        )
    )
    return role["Role"]["Arn"]


def _reap_log_group(ctx, fn: str) -> None:
    """Registered BEFORE the function exists, so LIFO runs it AFTER delete_function.

    delete_function does not remove /aws/lambda/<fn>, and a stream buffered by an invocation that
    already returned can flush after the delete and RECREATE the group (measured: the group can
    first appear ~8 s after the last log event), so this re-deletes until four consecutive reads
    5 s apart find it absent, and raises when its budget runs out.
    """
    group = f"/aws/lambda/{fn}"

    def _reap() -> None:
        logs = ctx.client("logs")
        deadline = time.monotonic() + 120.0
        absent = 0
        while absent < 4:
            groups = logs.describe_log_groups(logGroupNamePrefix=group)["logGroups"]
            if any(g["logGroupName"] == group for g in groups):
                absent = 0
                try:
                    logs.delete_log_group(logGroupName=group)
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                        raise
            else:
                absent += 1
            if absent < 4:
                if time.monotonic() > deadline:
                    raise AssertionError(f"log group {group} still present after 120s of deletes")
                time.sleep(5)

    ctx.on_cleanup(_reap)


def _create_function(ctx, lam, **kwargs) -> dict:
    """CreateFunction, retrying only the documented role-propagation refusal; raises on deadline."""
    name = kwargs["FunctionName"]
    _reap_log_group(ctx, name)
    left = ctx.time_left()
    deadline = time.monotonic() + (120.0 if left is None else min(120.0, left))
    last = None
    while time.monotonic() < deadline:
        try:
            created = lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") != "InvalidParameterValueException" or "role" not in err.get(
                "Message", ""
            ).lower():
                raise
            last = exc
            time.sleep(2)
            continue
        ctx.on_cleanup(
            _teardown(lambda: lam.delete_function(FunctionName=name), "ResourceNotFoundException")
        )
        _wait_ready(lam, name)
        return created
    raise AssertionError(f"CreateFunction({name}) never succeeded within 120s; last error {last}")


def _publish_layer(ctx, lam, layer_name: str, zip_bytes: bytes, **kwargs) -> dict:
    """PublishLayerVersion with its delete registered at once (DeleteLayerVersion is idempotent)."""
    published = lam.publish_layer_version(
        LayerName=layer_name,
        Content={"ZipFile": zip_bytes},
        Description=f"sim2real {CHECK}",
        **kwargs,
    )
    version = published["Version"]
    ctx.on_cleanup(lambda: lam.delete_layer_version(LayerName=layer_name, VersionNumber=version))
    return published


def _wait_ready(lam, name: str, timeout_s: float = 180.0) -> dict:
    """Poll until State=Active and the last update is Successful; a Failed state raises."""
    deadline = time.monotonic() + timeout_s
    cfg: dict = {}
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg.get("State") == "Failed" or cfg.get("LastUpdateStatus") == "Failed":
            raise AssertionError(
                f"{name} failed: State={cfg.get('State')!r} {cfg.get('StateReason')!r} "
                f"LastUpdateStatus={cfg.get('LastUpdateStatus')!r} "
                f"{cfg.get('LastUpdateStatusReason')!r}"
            )
        if cfg.get("State") == "Active" and cfg.get("LastUpdateStatus") in (None, "Successful"):
            return cfg
        time.sleep(2)
    raise AssertionError(f"{name} not ready within {timeout_s}s; last saw {cfg.get('State')!r}")


def _invoke(lam, fn: str, payload: dict | None = None, qualifier: str | None = None):
    """``(FunctionError or None, parsed payload)`` of one synchronous invocation."""
    kwargs = {"FunctionName": fn, "Payload": json.dumps(payload or {}).encode()}
    if qualifier is not None:
        kwargs["Qualifier"] = qualifier
    resp = lam.invoke(**kwargs)
    assert resp["StatusCode"] == 200, f"Invoke of {fn} returned StatusCode {resp['StatusCode']}"
    body = resp["Payload"].read().decode()
    return resp.get("FunctionError"), json.loads(body)


def _invoke_ok(lam, fn: str, payload: dict | None = None, qualifier: str | None = None):
    error, body = _invoke(lam, fn, payload, qualifier)
    assert error is None, f"{fn} raised ({error}) instead of returning: {str(body)[:600]}"
    return body


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
