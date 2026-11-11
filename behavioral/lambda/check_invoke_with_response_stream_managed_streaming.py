"""invoke-with-response-stream-managed-streaming."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "invoke-with-response-stream-managed-streaming"
GROUP = "server-side"
SERVICES = ["lambda"]

_HANDLER_JS = """
const { setTimeout: sleep } = require('timers/promises');

exports.handler = awslambda.streamifyResponse(async (event, responseStream, _context) => {
  for (let i = 0; i < 4; i++) {
    responseStream.write(`chunk-${i}\\n`);
    if (i < 3) {
      await sleep(700);
    }
  }
  responseStream.end();
});
"""


@tags("axis:happy-path", "cap:c3", "cap:c6", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """InvokeWithResponseStream delivers chunks progressively as the function produces them,
    not buffered into a single blob delivered only at completion."""
    lam = ctx.client("lambda")
    iam = ctx.client("iam")

    try:
        role_arn = _create_basic_execution_role(ctx, iam)
        function_name = ctx.unique_name("sim2real-behav-streamfn-")
        code_zip = _make_zip({"index.js": _HANDLER_JS})
        _create_function_with_retry(
            ctx,
            lam,
            FunctionName=function_name,
            Runtime="nodejs22.x",
            Role=role_arn,
            Handler="index.handler",
            Code={"ZipFile": code_zip},
            Timeout=30,
            MemorySize=128,
            Tags={"sim2real:managed": "true", "sim2real:check": CHECK},
        )
        ctx.on_cleanup(lambda: _delete_function_log_group(ctx, function_name))
        ctx.on_cleanup(lambda: lam.delete_function(FunctionName=function_name))
        _wait_for_active(lam, function_name)
    except AssertionError:
        raise
    except Exception as exc:  # noqa: BLE001 - environment/prerequisite failure
        raise AssertionError(f"unreachable: could not provision response-streaming function: {exc}") from exc

    try:
        resp = lam.invoke_with_response_stream(
            FunctionName=function_name,
            InvocationType="RequestResponse",
            Payload=b"{}",
        )
    except ClientError as exc:
        raise AssertionError(f"unreachable: InvokeWithResponseStream unsupported here: {exc}") from exc

    assert resp["StatusCode"] == 200, resp["StatusCode"]

    chunk_times: list[float] = []
    t_start = time.monotonic()
    saw_complete = False
    for event in resp["EventStream"]:
        if "PayloadChunk" in event:
            chunk_times.append(time.monotonic() - t_start)
        elif "InvokeComplete" in event:
            saw_complete = True
            break

    assert saw_complete, "stream never delivered an InvokeComplete event"
    assert len(chunk_times) >= 3, f"expected >=3 progressive chunks, got {len(chunk_times)}: {chunk_times}"

    # If the emulator buffered the whole response and released it only once, all chunk
    # arrival timestamps would cluster together near the end. A managed, truly-streamed
    # runtime spreads arrivals out over the ~2.1s the handler spends sleeping between writes.
    spread = chunk_times[-1] - chunk_times[0]
    assert spread >= 1.0, f"chunks arrived within {spread:.3f}s of each other - looks buffered, not streamed: {chunk_times}"

    max_gap = max(b - a for a, b in zip(chunk_times, chunk_times[1:]))
    assert max_gap >= 0.4, f"no inter-chunk gap >= 0.4s observed ({max_gap:.3f}s) - response looks buffered: {chunk_times}"


# ===== helpers =====

def _make_zip(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


def _create_basic_execution_role(ctx, iam) -> str:
    role_name = ctx.unique_name("sim2real-behav-streamrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role["Role"]["Arn"]


def _create_function_with_retry(ctx, lam, **kwargs):
    last_exc = None
    for _ in range(10):
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("InvalidParameterValueException", "ResourceConflictException"):
                last_exc = exc
                time.sleep(3)
                continue
            raise
    raise last_exc


def _wait_for_active(lam, name: str, timeout_s: float = 120.0) -> dict:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg.get("State") == "Active" and cfg.get("LastUpdateStatus") in (None, "Successful"):
            return cfg
        if cfg.get("State") == "Failed":
            raise AssertionError(f"function entered Failed state: {cfg.get('StateReason')}")
        time.sleep(2)
    raise AssertionError(f"function {name} did not become Active within {timeout_s}s")


def _delete_function_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates for a function on its first invocation and never
    deletes. Registered before the function's own teardown, so it runs after the function is
    gone; the service can still create the group from logs it delivers a few seconds later, so
    the group must stay absent across two reads 5 s apart. Only an already-absent group is
    tolerated; a group still present after 30 s raises."""
    import time

    from botocore.exceptions import ClientError

    logs = ctx.client("logs")
    group = f"/aws/lambda/{function_name}"

    def present() -> bool:
        found = logs.describe_log_groups(logGroupNamePrefix=group)["logGroups"]
        return any(g["logGroupName"] == group for g in found)

    deadline = time.monotonic() + 30.0
    while True:
        try:
            logs.delete_log_group(logGroupName=group)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        time.sleep(5.0)
        if not present():
            time.sleep(5.0)
            if not present():
                return
        if time.monotonic() >= deadline:
            raise RuntimeError(f"log group {group} still present 30 s after delete_log_group")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
