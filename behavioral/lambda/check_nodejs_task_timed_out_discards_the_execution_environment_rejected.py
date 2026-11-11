"""nodejs-task-timed-out-discards-the-execution-environment-rejected."""

from __future__ import annotations

import base64
import io
import json
import re
import time
import zipfile

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = 'nodejs-task-timed-out-discards-the-execution-environment-rejected'
GROUP = 'nodejs-timeout'
SERVICES = ['lambda']

# A module-scope id, set once per execution environment and logged by every invoke, so the tail
# log names the environment even of an invoke that never returns. A hung invoke keeps the event
# loop busy with a recurring timer (an unresolved, pending-forever Promise would exit the process on its own
# before Timeout ever fires, which is a different, already-covered fidelity claim).
_HANDLER = r"""
const crypto = require('crypto');
const ENV_ID = crypto.randomBytes(8).toString('hex');
exports.handler = async (event) => {
  console.log(`probe-env ${ENV_ID}`);
  if (event.hang) {
    await new Promise(() => { const tick = () => setTimeout(tick, 50); tick(); });
  }
  return { envId: ENV_ID };
};
"""
_TIMEOUT_S = 5
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


def _deploy(ctx, lam, role: str) -> str:
    name = ctx.unique_name("sim2real-behav-fn-")
    logs = ctx.client("logs")
    ctx.on_cleanup(lambda n=name: _reap_log_group(logs, f"/aws/lambda/{n}"))
    deadline = time.monotonic() + 90
    while True:
        try:
            lam.create_function(
                FunctionName=name, Runtime="nodejs22.x", Handler="index.handler", Role=role,
                Code={"ZipFile": _zip({"index.js": _HANDLER})}, MemorySize=128,
                Timeout=_TIMEOUT_S, Tags={"sim2real": CHECK},
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
    return ctx.client("lambda", config=Config(read_timeout=60, retries={"mode": "standard"}))


_ENV_LINE = re.compile(r"probe-env ([0-9a-f]{16})")
#: Sequential ordinary invokes allowed for two consecutive ones to share an environment.
_WARM_TRIES = 6
#: Ordinary invokes after the timeout, none of which may land in the timed-out environment.
_AFTER_KILL = 3


def _invoke(lam, fn, payload) -> tuple[dict, dict, list[str]]:
    resp = lam.invoke(FunctionName=fn, LogType="Tail", Payload=json.dumps(payload).encode())
    assert resp["StatusCode"] == 200, f"Invoke {fn}: StatusCode {resp['StatusCode']!r}"
    body = json.loads(resp["Payload"].read())
    log = base64.b64decode(resp.get("LogResult", "")).decode("utf-8", "replace")
    return resp, body, _ENV_LINE.findall(log)


def _ordinary(lam, fn) -> str:
    resp, body, _ = _invoke(lam, fn, {"hang": False})
    assert not resp.get("FunctionError"), f"an ordinary invoke failed: {body!r}"
    return body["envId"]


# timing:real-time — workflow: 5 s https://docs.aws.amazon.com/lambda/latest/dg/configuration-timeout.html
@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A Node.js handler overrunning Timeout fails with errorType Sandbox.Timedout and the exact
    "Task timed out after 5.00 seconds" message, and the timed-out environment is discarded: its
    module-scope id never serves another invoke.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/configuration-timeout.html
    Reference: https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtime-environment.html
    """
    lam = ctx.client("lambda")
    invoker = _invoker(ctx)
    fn = _deploy(ctx, lam, _exec_role(ctx))

    # Warm up until two consecutive invokes share an environment, so the hang most likely lands in
    # a warm one; AWS guarantees no reuse, so reaching the bound without a repeat is not a failure.
    last = None
    for _ in range(_WARM_TRIES):
        env = _ordinary(invoker, fn)
        if env == last:
            break
        last = env

    resp, body, envs = _invoke(invoker, fn, {"hang": True})
    assert resp.get("FunctionError") == "Unhandled", (
        f"FunctionError={resp.get('FunctionError')!r}, expected 'Unhandled': {body!r}"
    )
    assert body.get("errorType") == "Sandbox.Timedout", f"errorType: {body!r}"
    rid = resp["ResponseMetadata"]["RequestId"]
    want = f"RequestId: {rid} Error: Task timed out after {_TIMEOUT_S}.00 seconds"
    assert body.get("errorMessage") == want, (
        f"errorMessage {body.get('errorMessage')!r}, expected {want!r}"
    )
    assert len(envs) == 1, (
        f"the hung invoke logs its environment id once before hanging; its tail log carried {envs!r}"
    )
    killed = envs[0]

    for _ in range(_AFTER_KILL):
        env = _ordinary(invoker, fn)
        assert env != killed, (
            f"an invoke after the timeout ran in the timed-out environment {killed!r}; AWS discards "
            f"it and runs later invokes in an environment with reinitialized module state"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
