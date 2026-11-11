"""custom-runtime-raw-response-post-over-6mb-rejected-platform-enforced."""

from __future__ import annotations

import json
import time
import zipfile
import io

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = 'custom-runtime-raw-response-post-over-6mb-rejected-platform-enforced'
GROUP = 'runtime_api'
SERVICES = ['lambda']

_BIG_BYTES = 7 * 1024 * 1024
_EXPECTED_MESSAGE = "Response payload size exceeded maximum allowed payload size (6291556 bytes)."

# A shell runtime that, for an event carrying "bytes", builds that many bytes with dd/tr and POSTs
# them to .../response with no SDK and no buffering layer of its own; any other event gets a small
# reply. Either way it then prints the HTTP status the Runtime API answered that POST with, keyed by
# the invoke's request id, so the status is read from the same invoke's CloudWatch Logs delivery.
BOOTSTRAP = r'''#!/bin/sh
API="$AWS_LAMBDA_RUNTIME_API"
while true; do
  curl -sS -D /tmp/h -o /tmp/e "http://$API/2018-06-01/runtime/invocation/next"
  RID=$(grep -i '^lambda-runtime-aws-request-id:' /tmp/h | tr -d '\r' | sed 's/^[^:]*: *//')
  EVENT=$(cat /tmp/e)
  case "$EVENT" in
    *'"bytes"'*)
      BYTES=$(printf '%s' "$EVENT" | sed -n 's/.*"bytes"[ ]*:[ ]*\([0-9][0-9]*\).*/\1/p')
      KB=$((BYTES / 1024))
      dd if=/dev/zero bs=1024 count="$KB" 2>/dev/null | tr '\0' 'x' > /tmp/body
      ;;
    *)
      printf '{"ok":true,"rid":"%s"}' "$RID" > /tmp/body
      ;;
  esac
  CODE=$(curl -sS -o /dev/null -w '%{http_code}' -X POST --data-binary @/tmp/body \
    "http://$API/2018-06-01/runtime/invocation/$RID/response")
  echo "post-status:$RID:$CODE"
done
'''

_BASIC_EXEC = "arn:{partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
_ROLE_NOT_READY = "The role defined for the function cannot be assumed by Lambda."


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


def _reap_log_group(ctx, group):
    """delete_function leaves /aws/lambda/<fn>, and a buffered stream can flush after the delete
    and RECREATE it: re-delete until the group stays absent for a quiet window (bounded)."""

    def _reap():
        logs = ctx.client("logs")
        deadline = time.monotonic() + 40.0
        absent = 0
        while absent < 3:
            found = logs.describe_log_groups(logGroupNamePrefix=group).get("logGroups", [])
            if any(g["logGroupName"] == group for g in found):
                absent = 0
                try:
                    logs.delete_log_group(logGroupName=group)
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                        raise
            else:
                absent += 1
            if absent < 3:
                if time.monotonic() > deadline:
                    raise AssertionError(f"log group {group} still present after 40s")
                time.sleep(4)

    ctx.on_cleanup(_reap)


def _make_zip(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data, mode in entries:
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = mode << 16
            zf.writestr(info, data)
    return buf.getvalue()


def _execution_role(ctx, iam):
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                       "Action": "sts:AssumeRole"}],
    })
    name = ctx.unique_name("sim2real-behav-rsz-role-")
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=trust,
                          Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    partition = ctx.client("sts").get_caller_identity()["Arn"].split(":")[1]
    policy = _BASIC_EXEC.format(partition=partition)
    iam.attach_role_policy(RoleName=name, PolicyArn=policy)
    ctx.on_cleanup(_teardown(
        lambda: iam.detach_role_policy(RoleName=name, PolicyArn=policy), "NoSuchEntity"))
    return arn


def _create_function(ctx, lam, **kwargs):
    name = kwargs["FunctionName"]
    _reap_log_group(ctx, f"/aws/lambda/{name}")
    deadline = time.monotonic() + 120
    while True:
        try:
            lam.create_function(**kwargs)
            break
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] != "InvalidParameterValueException" or err.get("Message") != (
                    _ROLE_NOT_READY) or time.monotonic() > deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name),
                             "ResourceNotFoundException"))
    return _wait_ready(lam, name)


def _wait_ready(lam, name, timeout_s=180):
    deadline = time.monotonic() + timeout_s
    cfg = None
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        assert cfg["State"] != "Failed", f"{name} entered State=Failed: {cfg.get('StateReason')!r}"
        if cfg["State"] == "Active":
            return cfg
        time.sleep(1)
    raise AssertionError(f"{name} did not reach State=Active within {timeout_s}s: {cfg!r}")


def _invoke(lam, name, payload):
    resp = lam.invoke(FunctionName=name, Payload=json.dumps(payload).encode())
    raw = resp["Payload"].read()
    return {
        "status": resp["StatusCode"],
        "function_error": resp.get("FunctionError"),
        "raw": raw,
        "rid": resp["ResponseMetadata"]["RequestId"],
    }


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the check's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the check's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _post_status(ctx, logs, group, rid):
    """The status the bootstrap logged for its POST to .../response in invoke ``rid``."""
    prefix = f"post-status:{rid}:"
    deadline = time.monotonic() + _budget_s(ctx, 180)
    while True:
        kw = {"logGroupName": group, "filterPattern": f'"{prefix}"'}
        found = []
        try:
            while True:
                page = logs.filter_log_events(**kw)
                found += [e["message"] for e in page.get("events", []) if prefix in e["message"]]
                if not page.get("nextToken"):
                    break
                kw["nextToken"] = page["nextToken"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        if found:
            return found[0].split(prefix, 1)[1].strip()
        if time.monotonic() > deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"{prefix} in {group}: the run budget ended first; not graded")
            raise AssertionError(f"the bootstrap's {prefix} line never reached {group}")
        time.sleep(2)


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A custom runtime POSTing a 7 MB response to the Runtime API gets 413 from that POST in the
    same invoke, whose caller sees FunctionError=Unhandled, Function.ResponseSizeTooLarge and the
    documented message; a small response gets 202. https://docs.aws.amazon.com/lambda/latest/dg/runtimes-api.html
    """
    lam = ctx.client("lambda", config=Config(read_timeout=90))
    logs = ctx.client("logs")
    iam = ctx.client("iam")
    role_arn = _execution_role(ctx, iam)
    fn = ctx.unique_name("sim2real-behav-rsz-")
    group = f"/aws/lambda/{fn}"
    _create_function(
        ctx, lam, FunctionName=fn, Runtime="provided.al2023", Handler="bootstrap", Role=role_arn,
        Code={"ZipFile": _make_zip([("bootstrap", BOOTSTRAP, 0o100755)])},
        Architectures=["arm64"], MemorySize=512, Timeout=30, Tags={"sim2real": CHECK},
    )

    # Positive control: a small response is accepted (202) and returned to the caller.
    control = _invoke(lam, fn, {"control": True})
    assert control["status"] == 200 and not control["function_error"], (
        f"control invoke failed: status={control['status']!r} "
        f"function_error={control['function_error']!r} raw={control['raw']!r}")
    body = json.loads(control["raw"])
    assert body.get("ok") is True and body.get("rid") == control["rid"], (
        f"control invoke returned an unexpected body: {body!r} (request id {control['rid']!r})")
    code = _post_status(ctx, logs, group, control["rid"])
    assert code == "202", f"the Runtime API answered a small .../response POST with {code!r}, expected 202"

    # The runtime posts _BIG_BYTES straight to .../response.
    big = _invoke(lam, fn, {"bytes": _BIG_BYTES})
    assert big["status"] == 200, f"oversize-response invoke status {big['status']!r}"
    err = json.loads(big["raw"])
    assert (big["function_error"], err.get("errorType"), err.get("errorMessage")) == (
        "Unhandled", "Function.ResponseSizeTooLarge", _EXPECTED_MESSAGE), (
        f"oversize response: FunctionError={big['function_error']!r} "
        f"errorType={err.get('errorType')!r} errorMessage={err.get('errorMessage')!r}")
    code = _post_status(ctx, logs, group, big["rid"])
    assert code == "413", (
        f"the Runtime API answered the over-6 MB .../response POST with {code!r}; expected it to "
        f"refuse it synchronously with 413")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
