"""nodejs-v8-heap-exhaustion-aborts-distinct-from-os-level-out-of-memory-rejected."""

from __future__ import annotations

import base64
import io
import json
import time
import zipfile

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = 'nodejs-v8-heap-exhaustion-aborts-distinct-from-os-level-out-of-memory-rejected'
GROUP = 'nodejs-memory'
SERVICES = ['lambda']

# NODE_OPTIONS=--max-old-space-size sets V8's old-space ceiling far below a 1536 MB container, so
# growing a plain JS array past it aborts the process long before the container's own memory limit
# is touched. A Buffer lives outside that heap, so filling one well past a small MemorySize instead
# hits the container's own cgroup limit.
_HANDLER = r"""
exports.handler = async (event) => {
  if (event.offHeap) {
    const bufs = [];
    for (let i = 0; i < event.chunks; i++) {
      const block = Buffer.alloc(8 * 1024 * 1024);
      block.fill(1);
      bufs.push(block);
    }
    return { held: bufs.length };
  }
  if (event.limits) {
    return { heapLimitBytes: require('v8').getHeapStatistics().heap_size_limit };
  }
  const chunks = [];
  for (let i = 0; i < event.chunks; i++) {
    const block = new Array(1000000).fill('x');
    chunks.push(block);
  }
  return { held: chunks.length };
};
"""

#: V8 old-space ceilings, in MB, set explicitly on each function.
_OLD_SPACE_MB = 256
_OFFHEAP_OLD_SPACE_MB = 64
_SMALL_CHUNKS = 5
_LARGE_CHUNKS = 2000
_MEMORY_MB = 1536
_OFFHEAP_MEMORY_MB = 128
_OFFHEAP_SMALL_CHUNKS = 8
_OFFHEAP_LARGE_CHUNKS = 50
_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
    ],
}
_BASIC_EXEC = "arn:{partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
_ROLE_NOT_READY = "The role defined for the function cannot be assumed by Lambda."


def _partition(ctx) -> str:
    arn = ctx.client("sts").get_caller_identity()["Arn"]
    parts = arn.split(":")
    assert len(parts) > 2 and parts[0] == "arn" and parts[1], f"GetCallerIdentity Arn {arn!r}"
    return parts[1]


def _exec_role(ctx):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-role-")
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(_TRUST),
                          Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    policy = _BASIC_EXEC.format(partition=_partition(ctx))
    iam.attach_role_policy(RoleName=name, PolicyArn=policy)
    ctx.on_cleanup(_teardown(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=policy), "NoSuchEntity"))
    return arn


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()``; only the resource's own not-found codes mean it is gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _reap_log_group(logs, name: str, *, reads: int = 3, interval_s: float = 5.0,
                    budget_s: float = 180.0) -> None:
    deadline = time.monotonic() + budget_s
    absent = 0
    while absent < reads:
        groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        if any(g["logGroupName"] == name for g in groups):
            absent = 0
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            absent += 1
        if absent < reads:
            assert time.monotonic() <= deadline, f"log group {name} still present after {budget_s}s"
            time.sleep(interval_s)


def _zip(files: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for path, src in files.items():
            zf.writestr(path, src)
    return buf.getvalue()


def _deploy(ctx, lam, role: str, memory_mb: int, old_space_mb: int) -> str:
    name = ctx.unique_name("sim2real-behav-fn-")
    logs = ctx.client("logs")
    ctx.on_cleanup(lambda n=name: _reap_log_group(logs, f"/aws/lambda/{n}"))
    deadline = time.monotonic() + 90
    while True:
        try:
            lam.create_function(
                FunctionName=name, Runtime="nodejs22.x", Handler="index.handler", Role=role,
                Code={"ZipFile": _zip({"index.js": _HANDLER})}, MemorySize=memory_mb, Timeout=30,
                Environment={"Variables": {"NODE_OPTIONS": f"--max-old-space-size={old_space_mb}"}},
                Tags={"sim2real": CHECK},
            )
            break
        except ClientError as exc:
            err = exc.response["Error"]
            propagating = (err["Code"] == "InvalidParameterValueException"
                           and err.get("Message") == _ROLE_NOT_READY)
            if not propagating or time.monotonic() > deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(_teardown(lambda n=name: lam.delete_function(FunctionName=n), "ResourceNotFoundException"))
    deadline = time.monotonic() + 90
    while True:
        cfg = lam.get_function_configuration(FunctionName=name)
        assert cfg["State"] != "Failed", f"{name} entered Failed: {cfg.get('StateReason')!r}"
        if cfg["State"] == "Active":
            return name
        assert time.monotonic() < deadline, f"{name} not Active within 90s"
        time.sleep(1)


def _invoker(ctx):
    """A Lambda client with standard retries; its read timeout outlasts every invoke it sends."""
    return ctx.client("lambda", config=Config(read_timeout=90, retries={"mode": "standard"}))


def _invoke(lam, fn, payload) -> tuple:
    resp = lam.invoke(FunctionName=fn, Payload=json.dumps(payload).encode(), LogType="Tail")
    raw = resp["Payload"].read()
    body = json.loads(raw)
    tail = base64.b64decode(resp.get("LogResult") or b"").decode("utf-8", "replace")
    return resp, body, tail, resp["ResponseMetadata"]["RequestId"]


def _report_line(tail, rid):
    lines = [ln for ln in tail.splitlines() if ln.startswith(f"REPORT RequestId: {rid}")]
    assert len(lines) == 1, f"expected one REPORT line for {rid!r} in the log tail:\n{tail}"
    return lines[0]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A plain array grown past the V8 heap set by NODE_OPTIONS --max-old-space-size aborts with
    Runtime.ExitError "signal: aborted"; an off-heap Buffer filled past MemorySize is the distinct
    cgroup kill, Runtime.OutOfMemory "signal: killed".

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/nodejs-exceptions.html
    Reference: https://docs.aws.amazon.com/lambda/latest/dg/configuration-memory.html
    """
    lam = ctx.client("lambda")
    invoker = _invoker(ctx)
    role = _exec_role(ctx)
    fn = _deploy(ctx, lam, role, _MEMORY_MB, _OLD_SPACE_MB)

    _, body, _, _ = _invoke(invoker, fn, {"limits": True})
    limit = body.get("heapLimitBytes")
    assert isinstance(limit, int) and limit < 2 * _OLD_SPACE_MB * 1024 * 1024, (
        f"--max-old-space-size={_OLD_SPACE_MB} must bound V8's heap far below MemorySize="
        f"{_MEMORY_MB}; heap_size_limit was {limit!r}"
    )
    _, body, _, _ = _invoke(invoker, fn, {"chunks": _SMALL_CHUNKS})
    assert body.get("held") == _SMALL_CHUNKS, f"positive control: small allocation failed: {body!r}"

    resp, body, tail, rid = _invoke(invoker, fn, {"chunks": _LARGE_CHUNKS})
    assert resp.get("FunctionError") == "Unhandled", (
        f"FunctionError={resp.get('FunctionError')!r}, expected 'Unhandled': {body!r}"
    )
    assert body.get("errorType") == "Runtime.ExitError", (
        f"errorType {body.get('errorType')!r}, expected 'Runtime.ExitError' (not "
        f"'Runtime.OutOfMemory', the cgroup-kill shape): {body!r}"
    )
    want = f"RequestId: {rid} Error: Runtime exited with error: signal: aborted"
    assert body.get("errorMessage") == want, (
        f"errorMessage {body.get('errorMessage')!r}, expected {want!r}"
    )
    assert "held" not in body, f"the aborted handler still returned a result: {body!r}"
    report = _report_line(tail, rid)
    assert "Error Type: Runtime.ExitError" in report.split("\t"), (
        f"the REPORT line does not record the V8 heap abort: {report!r}"
    )

    offheap_fn = _deploy(ctx, lam, role, _OFFHEAP_MEMORY_MB, _OFFHEAP_OLD_SPACE_MB)
    _, body, _, _ = _invoke(invoker, offheap_fn, {"offHeap": True, "chunks": _OFFHEAP_SMALL_CHUNKS})
    assert body.get("held") == _OFFHEAP_SMALL_CHUNKS, (
        f"positive control: small off-heap allocation failed: {body!r}"
    )
    resp, body, tail, rid = _invoke(invoker, offheap_fn, {"offHeap": True, "chunks": _OFFHEAP_LARGE_CHUNKS})
    assert resp.get("FunctionError") == "Unhandled", (
        f"FunctionError={resp.get('FunctionError')!r}, expected 'Unhandled': {body!r}"
    )
    assert body.get("errorType") == "Runtime.OutOfMemory", (
        f"errorType {body.get('errorType')!r}, expected 'Runtime.OutOfMemory' (not "
        f"'Runtime.ExitError', the V8-abort shape): {body!r}"
    )
    want = f"RequestId: {rid} Error: Runtime exited with error: signal: killed"
    assert body.get("errorMessage") == want, (
        f"errorMessage {body.get('errorMessage')!r}, expected {want!r}"
    )
    report = _report_line(tail, rid)
    assert "Error Type: Runtime.OutOfMemory" in report.split("\t"), (
        f"the REPORT line does not record the cgroup out-of-memory kill: {report!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
