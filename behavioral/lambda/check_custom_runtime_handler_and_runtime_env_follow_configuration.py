"""custom-runtime-handler-and-runtime-env-follow-configuration."""

from __future__ import annotations

import base64
import io
import json
import re
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "custom-runtime-handler-and-runtime-env-follow-configuration"
GROUP = 'data-plane'
SERVICES = ['lambda']

# The runtime reports the environment it was started with, a per-process boot id and its own loop
# counter: Lambda may recycle an environment at any time, so counters are only comparable per boot.
BOOTSTRAP = r'''#!/bin/sh
API="http://$AWS_LAMBDA_RUNTIME_API/2018-06-01/runtime/invocation"
BOOT=$(cat /proc/sys/kernel/random/uuid)
N=0
while true; do
  N=$((N+1))
  curl -sS -D /tmp/h -o /tmp/e "$API/next"
  RID=$(grep -i '^lambda-runtime-aws-request-id:' /tmp/h | tr -d '\r' | sed 's/^[^:]*: *//')
  printf '{"n":%s,"boot":"%s","handler":"%s","api":"%s","taskRoot":"%s","runtimeDir":"%s","pwd":"%s","mine":"%s","memory":"%s"}' \
    "$N" "$BOOT" "${_HANDLER-<unset>}" "${AWS_LAMBDA_RUNTIME_API-<unset>}" "${LAMBDA_TASK_ROOT-<unset>}" \
    "${LAMBDA_RUNTIME_DIR-<unset>}" "$(pwd)" "${PROBE_SETTING-<unset>}" "${AWS_LAMBDA_FUNCTION_MEMORY_SIZE-<unset>}" > /tmp/r
  curl -sS -o /dev/null -X POST --data-binary @/tmp/r "$API/$RID/response"
done
'''

_HOST_PORT = re.compile(r"[0-9A-Za-z.\-]+:[0-9]{1,5}")

_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})
_BASIC_EXEC = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
_ROLE_NOT_READY = "The role defined for the function cannot be assumed by Lambda."


def _teardown(undo, *not_found):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` means gone."""

    def run_undo():
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _reap_log_groups(logs, names, *, reads=3, interval_s=4.0, budget_s=40.0):
    """Delete every group in ``names`` until ``reads`` consecutive rounds find all absent.

    A log stream an invocation buffered can flush after the function is deleted and recreate its
    group, so one delete is one round, not a teardown. Raises if a group is still coming back.
    """
    deadline = time.monotonic() + budget_s
    absent = 0
    while absent < reads:
        present = [
            name for name in names
            if any(g["logGroupName"] == name
                   for g in logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"])
        ]
        for name in present:
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        absent = 0 if present else absent + 1
        if absent < reads:
            if time.monotonic() > deadline:
                raise AssertionError(f"log groups {present!r} still present after {budget_s}s")
            time.sleep(interval_s)


_LOG_GROUPS: list = []


def _log_groups(ctx):
    """This run's /aws/lambda group names; one reap, registered before the first function, covers all."""
    for owner, names in _LOG_GROUPS:
        if owner is ctx:
            return names
    names: list = []
    _LOG_GROUPS.append((ctx, names))
    logs = ctx.client("logs")
    # Registered BEFORE any create, so LIFO runs it after every function has been deleted.
    ctx.on_cleanup(lambda: _reap_log_groups(logs, names))
    return names


def _make_zip(entries):
    """A deployment zip with an explicit unix mode on every member."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data, mode in entries:
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = mode << 16
            zf.writestr(info, data)
    return buf.getvalue()


def _execution_role(ctx):
    """An execution role this check creates and deletes."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-l3-exec-")
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=_TRUST,
                          Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    iam.attach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC)
    ctx.on_cleanup(_teardown(
        lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC), "NoSuchEntity"))
    return arn


def _function(ctx, lam, role, label, zipbytes, *, runtime, handler, **extra):
    """Create a function, register its teardown and log-group reap, and wait for State=Active."""
    name = ctx.unique_name(f"sim2real-l3-{label}-")
    _log_groups(ctx).append(f"/aws/lambda/{name}")
    kwargs = dict(FunctionName=name, Runtime=runtime, Handler=handler, Role=role,
                  Code={"ZipFile": zipbytes}, MemorySize=256, Timeout=15,
                  Tags={"sim2real": CHECK})
    kwargs.update(extra)
    deadline = time.monotonic() + 90
    while True:
        try:
            lam.create_function(**kwargs)
            break
        except ClientError as exc:
            err = exc.response["Error"]
            # IAM propagation of the role created above exposes no condition to poll.
            if (err["Code"] != "InvalidParameterValueException"
                    or err["Message"] != _ROLE_NOT_READY or time.monotonic() > deadline):
                raise
            time.sleep(3)
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name),
                             "ResourceNotFoundException"))
    _wait_settled(lam, name)
    return name


def _wait_settled(lam, name, timeout_s=120):
    deadline = time.monotonic() + timeout_s
    while True:
        cfg = lam.get_function_configuration(FunctionName=name)
        assert cfg["State"] != "Failed", f"{name} entered State=Failed: {cfg.get('StateReason')!r}"
        if cfg["State"] == "Active" and cfg.get("LastUpdateStatus") in (None, "Successful"):
            return cfg
        assert time.monotonic() < deadline, (
            f"{name} did not settle within {timeout_s}s: State={cfg['State']!r} "
            f"LastUpdateStatus={cfg.get('LastUpdateStatus')!r}")
        time.sleep(1)


def _invoke(lam, name, payload, **extra):
    """Invoke synchronously with the log tail; ``payload`` is raw bytes or a JSON-able value."""
    body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    before_ms = time.time() * 1000.0
    resp = lam.invoke(FunctionName=name, Payload=body, LogType="Tail", **extra)
    after_ms = time.time() * 1000.0
    return {
        "status": resp["StatusCode"],
        "function_error": resp.get("FunctionError"),
        "raw": resp["Payload"].read(),
        "content_type": resp["ResponseMetadata"]["HTTPHeaders"].get("content-type"),
        "request_id": resp["ResponseMetadata"]["RequestId"],
        "log": base64.b64decode(resp.get("LogResult", "")).decode("utf-8", "replace"),
        "before_ms": before_ms,
        "after_ms": after_ms,
    }


def _ok(name, r):
    """The JSON body of a successful invoke; fails naming the error otherwise."""
    assert r["status"] == 200, f"{name}: StatusCode {r['status']!r}, payload {r['raw']!r}"
    assert r["function_error"] is None, (
        f"{name}: FunctionError={r['function_error']!r}, payload {r['raw'][:600]!r}")
    return json.loads(r["raw"])


def _failed(name, r):
    """The JSON error document of an invoke that must report FunctionError=Unhandled."""
    assert r["status"] == 200, f"{name}: StatusCode {r['status']!r}, payload {r['raw']!r}"
    assert r["function_error"] == "Unhandled", (
        f"{name}: FunctionError={r['function_error']!r} (expected 'Unhandled'), "
        f"payload {r['raw'][:600]!r}")
    return json.loads(r["raw"])


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A custom runtime is started with the Handler verbatim as _HANDLER, AWS_LAMBDA_RUNTIME_API and
    task root /var/task, counts invocations 1, 2, ... per runtime process, and a configuration
    update of Handler, MemorySize and variables is served by a new process that sees all three.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars.html
    """
    lam = ctx.client("lambda")
    role = _execution_role(ctx)
    fn = _function(ctx, lam, role, "rtenv", _make_zip([("bootstrap", BOOTSTRAP, 0o100755)]),
                   runtime="provided.al2023", handler="my.custom.entry::Point")

    first = [_ok(fn, _invoke(lam, fn, {"i": i})) for i in (1, 2)]
    env = first[0]
    assert env["handler"] == "my.custom.entry::Point", (
        f"the runtime saw _HANDLER={env['handler']!r}; a custom runtime must be handed the "
        f"configured Handler string verbatim")
    assert _HOST_PORT.fullmatch(env["api"]), (
        f"AWS_LAMBDA_RUNTIME_API was {env['api']!r}; it must be the host:port of the runtime API")
    assert env["taskRoot"] == "/var/task" and env["pwd"] == "/var/task", (
        f"the runtime saw LAMBDA_TASK_ROOT={env['taskRoot']!r} and cwd {env['pwd']!r}; both must "
        f"be /var/task, where the package is unpacked")
    assert env["runtimeDir"] == "/var/runtime", f"LAMBDA_RUNTIME_DIR={env['runtimeDir']!r}"
    assert env["mine"] == "<unset>", f"PROBE_SETTING is set before it was configured: {env!r}"
    assert env["memory"] == "256", f"AWS_LAMBDA_FUNCTION_MEMORY_SIZE={env['memory']!r}"
    per_boot: dict = {}
    for b in first:
        per_boot.setdefault(b["boot"], []).append(b["n"])
    assert all(ns == list(range(1, len(ns) + 1)) for ns in per_boot.values()), (
        f"loop counters per runtime process {per_boot!r}; each process counts its invocations "
        f"1, 2, ... in order")

    lam.update_function_configuration(
        FunctionName=fn, Handler="other.entry", MemorySize=320,
        Environment={"Variables": {"PROBE_SETTING": "configured"}})
    cfg = _wait_settled(lam, fn)
    assert cfg["Handler"] == "other.entry", f"the update was not applied: {cfg['Handler']!r}"

    after = _ok(fn, _invoke(lam, fn, {"i": 3}))
    assert after["n"] == 1 and after["boot"] not in per_boot, (
        f"after a configuration update the runtime reported loop counter {after['n']!r} under boot "
        f"{after['boot']!r} (before: {sorted(per_boot)!r}); the update must retire the old "
        f"environment, so a fresh runtime process starts at 1")
    assert after["handler"] == "other.entry", (
        f"the new environment saw _HANDLER={after['handler']!r}, not the updated 'other.entry'")
    assert after["mine"] == "configured", (
        f"the new environment saw PROBE_SETTING={after['mine']!r}, not the configured value")
    assert after["memory"] == "320", (
        f"the new environment saw AWS_LAMBDA_FUNCTION_MEMORY_SIZE={after['memory']!r}, not 320")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
