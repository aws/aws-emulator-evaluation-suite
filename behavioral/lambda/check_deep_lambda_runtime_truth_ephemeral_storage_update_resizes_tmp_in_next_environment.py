"""deep-lambda-runtime-truth-ephemeral-storage-update-resizes-tmp-in-next-environment."""
from __future__ import annotations

import errno
import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-lambda-runtime-truth-ephemeral-storage-update-resizes-tmp-in-next-environment"
GROUP = "ephemeral_storage"
SERVICES = ["lambda"]

_WRITE_MB = 700  # above a 512 MB /tmp, below a 1024 MB one

# The guest mints an environment id at INIT, then tries to write _WRITE_MB into /tmp in 1 MB
# blocks, reporting how far it got, the errno it stopped on, and statvfs, then frees the space.
_PROBE = """\
import errno
import os
import uuid

ENV_ID = uuid.uuid4().hex


def handler(event, context):
    st = os.statvfs("/tmp")
    total_mb = st.f_blocks * st.f_frsize // (1024 * 1024)
    path = "/tmp/sim2real-fill.bin"
    block = b"\\0" * (1024 * 1024)
    written, err = 0, None
    try:
        with open(path, "wb") as fh:
            for _ in range(int(event["mb"])):
                fh.write(block)
                fh.flush()
                written += 1
            os.fsync(fh.fileno())
    except OSError as exc:
        err = errno.errorcode.get(exc.errno, str(exc.errno))
    finally:
        if os.path.exists(path):
            os.unlink(path)
    return {"env_id": ENV_ID, "total_mb": total_mb, "written_mb": written, "error": err}
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


def _fill(lam, fn):
    resp = lam.invoke(FunctionName=fn, Payload=json.dumps({"mb": _WRITE_MB}).encode())
    raw = resp["Payload"].read()
    assert not resp.get("FunctionError"), (
        f"{fn} FunctionError={resp.get('FunctionError')!r}: {raw[:400]!r}")
    return json.loads(raw)


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """Resizing EphemeralStorage on an existing function resizes /tmp in the next environment: a
    700 MB write hits ENOSPC at 512 MB and completes after an update to 1024 MB.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/configuration-ephemeral-storage.html
    """
    lam = ctx.client("lambda")
    role_arn = _make_role(ctx)
    fn = ctx.unique_name("sim2real-behav-rt-eph-")
    _create_function(
        ctx, lam, role_arn, fn, Runtime="python3.12", Handler="index.handler",
        Code={"ZipFile": _zip({"index.py": _PROBE})}, MemorySize=512, Timeout=120,
        EphemeralStorage={"Size": 512},
    )

    # ---- break one thing: at 512 MB the write runs out of space ----
    small = _fill(lam, fn)
    # statvfs reports at least the configured size, up to 10 % above it (filesystem overhead).
    assert 512 <= small["total_mb"] <= 512 * 1.1, f"512 MB /tmp statvfs total: {small!r}"
    assert small["error"] == errno.errorcode[errno.ENOSPC], (
        f"a {_WRITE_MB} MB write into a 512 MB /tmp must stop with ENOSPC; got {small!r}")
    assert small["written_mb"] < _WRITE_MB, small

    # ---- positive: resize the same function; the next environment has room ----
    cfg = lam.update_function_configuration(FunctionName=fn, EphemeralStorage={"Size": 1024})
    assert cfg["EphemeralStorage"]["Size"] == 1024, f"update echo: {cfg['EphemeralStorage']!r}"
    cfg = _wait_ready(lam, fn)
    assert cfg["EphemeralStorage"]["Size"] == 1024, f"config after update: {cfg['EphemeralStorage']!r}"
    big = _fill(lam, fn)
    assert big["env_id"] != small["env_id"], (
        f"the resized function was served by the pre-update environment {big['env_id']!r}")
    assert 1024 <= big["total_mb"] <= 1024 * 1.1, f"1024 MB /tmp statvfs total: {big!r}"
    assert big["error"] is None and big["written_mb"] == _WRITE_MB, (
        f"after resizing to 1024 MB the same {_WRITE_MB} MB write must complete; got {big!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
