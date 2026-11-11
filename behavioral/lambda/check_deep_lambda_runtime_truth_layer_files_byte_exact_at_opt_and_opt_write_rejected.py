"""deep-lambda-runtime-truth-layer-files-byte-exact-at-opt-and-opt-write-rejected."""
from __future__ import annotations

import errno
import hashlib
import io
import json
import os
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-lambda-runtime-truth-layer-files-byte-exact-at-opt-and-opt-write-rejected"
GROUP = "layers"
SERVICES = ["lambda"]

# The guest inventories every regular file under /opt (path, size, sha256, permission bits),
# runs the layer's executable, imports the layer's module, and tries two writes into /opt.
_PROBE = """\
import errno
import hashlib
import os
import subprocess


def _inventory(root="/opt"):
    out = {}
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            full = os.path.join(dirpath, name)
            with open(full, "rb") as fh:
                data = fh.read()
            out[os.path.relpath(full, root)] = {
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "mode": oct(os.stat(full).st_mode & 0o777),
            }
    return out


def _try_write(path, mode):
    try:
        with open(path, mode) as fh:
            fh.write("sim2real")
        return {"ok": True}
    except OSError as exc:
        return {"ok": False, "errno": exc.errno, "name": errno.errorcode.get(exc.errno)}


def handler(event, context):
    result = {"inventory": _inventory()}
    try:
        import sim2real_layer_mod
        result["module"] = sim2real_layer_mod.VALUE
    except ImportError as exc:
        result["module"] = "ImportError:" + type(exc).__name__
    if os.path.exists("/opt/sim2real/tool.sh"):
        proc = subprocess.run(["/opt/sim2real/tool.sh", "arg1"], capture_output=True, text=True)
        result["tool"] = {"rc": proc.returncode, "out": proc.stdout.strip()}
    else:
        result["tool"] = None
    result["write_new"] = _try_write("/opt/sim2real-new.txt", "w")
    result["append_existing"] = _try_write("/opt/sim2real/deep/a/b/c.txt", "a")
    result["write_tmp"] = _try_write("/tmp/sim2real-control.txt", "w")
    return result
"""


_BASIC = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"


def _zip(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, body in files.items():
            zf.writestr(name, body)
    return buf.getvalue()


def _reap_log_group(ctx, group):
    """delete_function leaves /aws/lambda/<fn>, and a buffered stream can flush after the delete
    and RECREATE it: re-delete until the group stays absent for a 30 s quiet window (bounded)."""
    logs = ctx.client("logs")
    quiet = 0
    for _ in range(16):
        found = logs.describe_log_groups(logGroupNamePrefix=group).get("logGroups", [])
        if any(g["logGroupName"] == group for g in found):
            quiet = 0
            try:
                logs.delete_log_group(logGroupName=group)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            quiet += 1
            if quiet >= 6:
                return
        time.sleep(5)


def _make_role(ctx):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-rt-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                       "Action": "sts:AssumeRole"}],
    }
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.attach_role_policy(RoleName=name, PolicyArn=_BASIC)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_BASIC))
    return arn


def _wait_ready(lam, fn, timeout_s=180):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=fn)
        if last["State"] == "Failed" or last.get("LastUpdateStatus") == "Failed":
            raise AssertionError(f"{fn} failed: {last.get('StateReason')!r} "
                                 f"{last.get('LastUpdateStatusReason')!r}")
        if last["State"] == "Active" and last.get("LastUpdateStatus") in (None, "Successful"):
            return last
        time.sleep(1.0)
    raise AssertionError(f"{fn} never became Active/Successful in {timeout_s}s; last={last!r}")


def _create_function(ctx, lam, role_arn, name, **kwargs):
    ctx.on_cleanup(lambda: _reap_log_group(ctx, f"/aws/lambda/{name}"))
    deadline = time.monotonic() + 120
    while True:
        try:
            lam.create_function(FunctionName=name, Role=role_arn,
                                Tags={"sim2real": CHECK}, **kwargs)
            break
        except ClientError as exc:
            msg = exc.response["Error"].get("Message", "")
            # IAM propagation exposes no pollable condition; the bounded retry is the fix.
            if "cannot be assumed" in msg and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    return _wait_ready(lam, name)


def _invoke(lam, fn):
    resp = lam.invoke(FunctionName=fn, Payload=b"{}")
    raw = resp["Payload"].read()
    assert not resp.get("FunctionError"), (
        f"{fn} FunctionError={resp.get('FunctionError')!r}: {raw[:400]!r}")
    return json.loads(raw)


def _layer_zip():
    """Returns (zip bytes, expected inventory keyed by path relative to /opt)."""
    files = {
        "sim2real/data.bin": (os.urandom(96 * 1024), 0o644),
        "sim2real/tool.sh": (b"#!/bin/sh\necho sim2real-tool-$1\n", 0o755),
        "sim2real/deep/a/b/c.txt": (b"nested layer file\n", 0o644),
        "python/sim2real_layer_mod.py": (b"VALUE = 'from-the-layer'\n", 0o644),
    }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path, (data, mode) in files.items():
            info = zipfile.ZipInfo(path)
            info.external_attr = (0o100000 | mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, data)
    expected = {p: {"size": len(d), "sha256": hashlib.sha256(d).hexdigest(), "mode": oct(m)}
                for p, (d, m) in files.items()}
    return buf.getvalue(), expected


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A layer is extracted under /opt byte-exact (paths, sha256, readable, executables runnable),
    /opt rejects writes with EROFS while /tmp stays writable, and detaching removes its files.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/chapter-layers.html
    """
    lam = ctx.client("lambda")
    role_arn = _make_role(ctx)
    layer_zip, expected = _layer_zip()
    layer_name = ctx.unique_name("sim2real-behav-rt-layer-")
    pub = lam.publish_layer_version(
        LayerName=layer_name, Content={"ZipFile": layer_zip},
        CompatibleRuntimes=["python3.12"], Description="sim2real runtime-truth layer",
    )
    ctx.on_cleanup(lambda: lam.delete_layer_version(LayerName=layer_name,
                                                    VersionNumber=pub["Version"]))
    layer_arn = pub["LayerVersionArn"]

    fn = ctx.unique_name("sim2real-behav-rt-opt-")
    _create_function(
        ctx, lam, role_arn, fn, Runtime="python3.12", Handler="index.handler",
        Code={"ZipFile": _zip({"index.py": _PROBE})}, MemorySize=256, Timeout=30,
        Layers=[layer_arn],
    )

    seen = _invoke(lam, fn)
    inv = seen["inventory"]
    assert set(inv) == set(expected), (
        f"/opt does not hold exactly the packaged paths: extra={sorted(set(inv) - set(expected))!r} "
        f"missing={sorted(set(expected) - set(inv))!r}")
    for path, want in expected.items():
        got = inv[path]
        assert got["size"] == want["size"] and got["sha256"] == want["sha256"], (
            f"/opt/{path} bytes differ from the package: got {got!r}, packaged {want!r}")
        # Permission bits are not preserved verbatim (0644 reads back 0755), so only
        # readability and the exec bit of an executable are asserted.
        mode = int(got["mode"], 8)
        assert mode & 0o444 == 0o444, f"/opt/{path} is not world-readable: {got['mode']!r}"
        if int(want["mode"], 8) & 0o111:
            assert mode & 0o111 == 0o111, (
                f"/opt/{path} was packaged executable ({want['mode']}) but is {got['mode']!r}")
    assert seen["module"] == "from-the-layer", f"layer module import: {seen['module']!r}"
    assert seen["tool"] == {"rc": 0, "out": "sim2real-tool-arg1"}, (
        f"the layer's packaged executable did not run as packaged: {seen['tool']!r}")

    # ---- /opt refuses writes; /tmp is the positive control ----
    assert seen["write_tmp"] == {"ok": True}, f"/tmp write control failed: {seen['write_tmp']!r}"
    for label in ("write_new", "append_existing"):
        res = seen[label]
        assert res.get("ok") is False and res.get("errno") == errno.EROFS, (
            f"{label} into /opt must fail with EROFS ({errno.EROFS}); got {res!r}")

    # ---- break one thing: detach the layer; its files must be gone from the next env ----
    lam.update_function_configuration(FunctionName=fn, Layers=[])
    cfg = _wait_ready(lam, fn)
    assert not cfg.get("Layers"), f"Layers still attached after detach: {cfg.get('Layers')!r}"
    after = _invoke(lam, fn)
    assert after["inventory"] == {}, (
        f"a detached layer's files are still visible under /opt: {sorted(after['inventory'])!r}")
    assert after["module"] == "ImportError:ModuleNotFoundError", (
        f"the detached layer's module is still importable: {after['module']!r}")
    assert after["tool"] is None, f"the detached layer's executable still exists: {after['tool']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
