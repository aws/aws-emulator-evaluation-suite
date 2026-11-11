"""layer-published-version-keeps-its-layer-after-latest-repoints-and-layer-deleted."""

from __future__ import annotations

import io
import json
import time
import uuid
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "layer-published-version-keeps-its-layer-after-latest-repoints-and-layer-deleted"
GROUP = "layers_runtime"
SERVICES = ["lambda"]

_HANDLER = """\
def handler(event, context):
    import sim2real_l8_snap as mod

    return {"token": mod.stamp(), "file": mod.__file__}
"""


def _module(token: str) -> str:
    return f'T = "{token}"\n\n\ndef stamp():\n    return T[::-1]\n'


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A published version snapshots its layer list: after $LATEST is repointed to another layer and
    the version's layer version is deleted, the published version still imports the deleted
    layer's bytes, while $LATEST imports the new layer's.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/API_DeleteLayerVersion.html
    """
    lam = ctx.client("lambda")
    iam = ctx.client("iam")
    token_a = uuid.uuid4().hex
    token_b = uuid.uuid4().hex

    role_arn = _create_execution_role(ctx, iam)
    layer_a_name = ctx.unique_name("sim2real-behav-l8-snapa-")
    layer_a = _publish_layer(
        ctx, lam, layer_a_name, _zip({"python/sim2real_l8_snap.py": _module(token_a)}),
        CompatibleRuntimes=["python3.12"],
    )
    layer_b = _publish_layer(
        ctx, lam, ctx.unique_name("sim2real-behav-l8-snapb-"),
        _zip({"python/sim2real_l8_snap.py": _module(token_b)}),
        CompatibleRuntimes=["python3.12"],
    )
    fn = ctx.unique_name("sim2real-behav-l8-snapfn-")
    _create_function(
        ctx, lam,
        FunctionName=fn, Runtime="python3.12", Role=role_arn, Handler="index.handler",
        Code={"ZipFile": _zip({"index.py": _HANDLER})}, Layers=[layer_a["LayerVersionArn"]],
        Timeout=30, MemorySize=128, Tags={"sim2real": CHECK},
    )
    published = lam.publish_version(FunctionName=fn)
    version = published["Version"]
    assert version == "1", f"the first published version must be '1', got {version!r}"
    assert [ly["Arn"] for ly in published.get("Layers", [])] == [layer_a["LayerVersionArn"]], (
        f"the published version must snapshot layer A; Layers={published.get('Layers')!r}"
    )

    lam.update_function_configuration(FunctionName=fn, Layers=[layer_b["LayerVersionArn"]])
    _wait_ready(lam, fn)
    lam.delete_layer_version(LayerName=layer_a_name, VersionNumber=layer_a["Version"])
    code, msg = _error(
        lambda: lam.get_layer_version(LayerName=layer_a_name, VersionNumber=layer_a["Version"])
    )
    assert (code, msg) == (
        "ResourceNotFoundException", "The resource you requested does not exist."
    ), f"layer A must be gone from the control plane after the delete; got {code!r} {msg!r}"

    latest = _invoke_ok(lam, fn)
    assert latest == {"token": token_b[::-1], "file": "/opt/python/sim2real_l8_snap.py"}, (
        f"$LATEST must import layer B's module; got {latest!r}"
    )
    pinned_cfg = lam.get_function_configuration(FunctionName=fn, Qualifier=version)
    assert [ly["Arn"] for ly in pinned_cfg.get("Layers", [])] == [layer_a["LayerVersionArn"]], (
        f"version {version} must still reference layer A; Layers={pinned_cfg.get('Layers')!r}"
    )
    pinned = _invoke_ok(lam, fn, qualifier=version)
    assert pinned == {"token": token_a[::-1], "file": "/opt/python/sim2real_l8_snap.py"}, (
        f"version {version} must still import the DELETED layer A's bytes (token reversed "
        f"{token_a[::-1]!r}); got {pinned!r}"
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
