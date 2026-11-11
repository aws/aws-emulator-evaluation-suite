"""layer-lib-dir-on-ld-library-path-loads-shared-object-by-bare-name."""

from __future__ import annotations

import base64
import io
import json
import random
import time
import zipfile
import zlib

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "layer-lib-dir-on-ld-library-path-loads-shared-object-by-bare-name"
GROUP = "layers_runtime"
SERVICES = ["lambda"]

# An x86-64 ELF shared object exporting `int sim2real_magic(int x) { return x * 7 + 3; }`, built
# with `gcc -shared -fPIC -O2 -nostdlib -s -Wl,--build-id=none -Wl,-z,noseparate-code
# -Wl,-z,max-page-size=0x1000`, then zlib-compressed and base64-encoded. It has no libc
# dependency, so it loads on any x86-64 Linux.
_SO_B64 = (
    "eNrtWEFL3EAUfkm2GrTiUiwUVMyhhV1qh+xSUVsQQdQepGy3tPS2RDc1QrNZkim4vSh46aXQY3+GP2HFi/g79B+o"
    "9KLpZPfNmpluqi3S03ww+fIy75s3My+X93aW11Z0TQMOAxbg2gJYRP6RT3+bA5M9h2Go43sPsnGmiwy4TqIbYKMy"
    "2rUrUyLvg8hcp/+lzkTO4djFfchsg8hc9/aU1v9FV0HdPvrJPAYi55DfMN0A3B48LVWMd9t74TnW8Z3nIw+6ML98"
    "cnzwp/iJ3wO2+yaea4RPRFt+OXSdTzXf2dza6Pl/y10mVPy51zYO8dwW/kOrr9+x9bR2Tthf1+7FGzdejuF8O45j"
    "W7pH7UsVtO28Nn5/0Pyude9ngo2vzHcEFBQUFBQUFBQUFBQU7g7nV3HQK6xStfEHtHltV0B7SKrjhpEf/af9ri4t"
    "vbAKrPIqWqUSmSG2VbbLz+3Z0rxVqLp165VDceLZTBGARF5EQ+qsA9lsfCaeE3lA6q1G1PK7TEMg1N2mQBoBdTtO"
    "zTBouiFtAXG92sfQ8d2aVw+vrY7Q8VmRSDYC33cb9A7OldzjRRwHvO3A88H5sfTZlPQPcQ1dyldBqvsNrEVNKW+T"
    "OKdL+eec71NHp/EkVZMn4PX1b3U29F/vKRuDqfhZfQvIOP8Cxuf6rP4FSP0LjjVJf6SLPH1D/Pd4dgOkfsao2Mcw"
    "JD2/hxrGtzMaJiTj/tNs9PmvCOq9G/L3C1Upd74="
)

_HANDLER = """\
import ctypes
import os


def handler(event, context):
    out = {"ld_library_path": os.environ.get("LD_LIBRARY_PATH", "").split(":")}
    lib = ctypes.CDLL(event["lib"])
    lib.sim2real_magic.restype = ctypes.c_int
    lib.sim2real_magic.argtypes = [ctypes.c_int]
    out["result"] = lib.sim2real_magic(event["x"])
    return out
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A layer's `lib/` directory is on LD_LIBRARY_PATH: a shared object at `lib/<name>.so` loads by
    its bare name and executes, while the same bytes elsewhere in the layer load only by absolute
    path and their bare name raises OSError "cannot open shared object file".

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/packaging-layers.html
    """
    lam = ctx.client("lambda")
    iam = ctx.client("iam")
    so = zlib.decompress(base64.b64decode("".join(_SO_B64)))
    assert so[:4] == b"\x7fELF", f"the embedded shared object is not an ELF: {so[:4]!r}"
    x = random.randint(1000, 99999)

    role_arn = _create_execution_role(ctx, iam)
    layer = _publish_layer(
        ctx, lam, ctx.unique_name("sim2real-behav-l8-lib-"),
        _make_zip([
            ("lib/libsim2real_l8.so", so, 0o100755),
            ("native/libsim2real_l8_other.so", so, 0o100755),
        ]),
        CompatibleRuntimes=["python3.12"],
        CompatibleArchitectures=["x86_64"],
    )
    fn = ctx.unique_name("sim2real-behav-l8-libfn-")
    _create_function(
        ctx, lam,
        FunctionName=fn, Runtime="python3.12", Role=role_arn, Handler="index.handler",
        Architectures=["x86_64"], Code={"ZipFile": _zip({"index.py": _HANDLER})},
        Layers=[layer["LayerVersionArn"]], Timeout=30, MemorySize=128, Tags={"sim2real": CHECK},
    )

    out = _invoke_ok(lam, fn, {"lib": "libsim2real_l8.so", "x": x})
    assert out["result"] == x * 7 + 3, (
        f"the layer library loaded by bare name must compute {x} * 7 + 3 = {x * 7 + 3}; the "
        f"handler returned {out!r}"
    )
    assert "/opt/lib" in out["ld_library_path"], (
        f"LD_LIBRARY_PATH must contain /opt/lib; it was {out['ld_library_path']!r}"
    )

    by_path = _invoke_ok(lam, fn, {"lib": "/opt/native/libsim2real_l8_other.so", "x": x})
    assert by_path["result"] == x * 7 + 3, (
        f"the copy outside lib/ must load by absolute path (it was extracted); got {by_path!r}"
    )

    error, body = _invoke(lam, fn, {"lib": "libsim2real_l8_other.so", "x": x})
    assert error == "Unhandled", (
        f"dlopen of a bare name that is only outside lib/ must raise; FunctionError={error!r}, "
        f"payload {body!r}"
    )
    assert body.get("errorType") == "OSError", f"expected errorType 'OSError'; payload {body!r}"
    assert body.get("errorMessage") == (
        "libsim2real_l8_other.so: cannot open shared object file: No such file or directory"
    ), f"the loader must report the bare name as not found; got {body.get('errorMessage')!r}"


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
