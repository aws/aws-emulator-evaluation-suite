"""execution-environment-contract-provided-al2023."""

from __future__ import annotations

import base64
import io
import json
import re
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execution-environment-contract-provided-al2023"
GROUP = "execution_environment"
SERVICES = ["lambda"]

_RUNTIME = "provided.al2023"
_MEMORY_MB = 256
_LARGE_EPHEMERAL_MB = 1024
_SMALL_EPHEMERAL_MB = 512
_RUNTIME_API_VERSION = "2018-06-01"

# A bootstrap with no toolchain beyond /bin/sh, curl and df, all present in provided.al2023: it
# answers the Lambda Runtime API itself. The execution environment emits the platform
# START/END/REPORT lines around whatever a custom runtime does, same as a managed one.
_BOOTSTRAP = r"""#!/bin/sh
set -u
API="http://$AWS_LAMBDA_RUNTIME_API/""" + _RUNTIME_API_VERSION + r"""/runtime/invocation"
while true; do
  HDR=/tmp/probe-hdr
  BODY=/tmp/probe-body
  curl -sS -D "$HDR" -o "$BODY" "$API/next"
  RID=$(grep -i '^lambda-runtime-aws-request-id:' "$HDR" | tr -d '\r' | sed 's/^[^:]*: *//')
  TMP_KB=$(df -Pk /tmp | tail -1 | awk '{print $2}')
  PAYLOAD="{\"memMb\":$AWS_LAMBDA_FUNCTION_MEMORY_SIZE,\"tmpTotalMb\":$((TMP_KB / 1024))}"
  curl -sS -o /dev/null -X POST -d "$PAYLOAD" "$API/$RID/response"
done
"""

_BASIC_EXEC = "arn:{partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
_ROLE_PROPAGATION = "cannot be assumed by Lambda"
_REPORT_RE = re.compile(
    r"REPORT RequestId: [0-9a-f-]{36}\t"
    r"Duration: (?P<dur>\d+\.\d{2}) ms\t"
    r"Billed Duration: (?P<billed>\d+) ms\t"
    r"Memory Size: (?P<mem>\d+) MB\t"
    r"Max Memory Used: (?P<maxmem>\d+) MB"
)


def _zip_bootstrap(script: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        info = zipfile.ZipInfo("bootstrap")
        info.external_attr = 0o755 << 16
        zf.writestr(info, script)
    return buf.getvalue()


def _teardown(undo, *not_found):
    """A cleanup running ``undo()``; only the resource's own not-found codes mean it is gone."""

    def run_undo():
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _make_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-pvenv-role-")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                       "Action": "sts:AssumeRole"}],
    })
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=trust, Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    partition = ctx.client("sts").get_caller_identity()["Arn"].split(":")[1]
    policy = _BASIC_EXEC.format(partition=partition)
    iam.attach_role_policy(RoleName=name, PolicyArn=policy)
    ctx.on_cleanup(_teardown(
        lambda: iam.detach_role_policy(RoleName=name, PolicyArn=policy), "NoSuchEntity"))
    return arn


def _reap_log_group(logs, group: str) -> None:
    quiet = 0
    for _ in range(14):
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
            if quiet >= 3:
                return
        time.sleep(4)
    raise AssertionError(f"log group {group} kept reappearing after delete")


def _wait_active(lam, name: str, timeout_s: float = 180.0) -> dict:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=name)
        if last.get("State") == "Failed":
            raise AssertionError(f"{name} entered Failed: {last.get('StateReason')!r}")
        if last.get("State") == "Active":
            return last
        time.sleep(1.5)
    raise AssertionError(f"{name} did not reach Active within {timeout_s}s; last={last!r}")


def _create_function(ctx, lam, logs, role_arn, *, ephemeral_mb: int, memory_mb: int) -> str:
    name = ctx.unique_name("sim2real-behav-pvenv-")
    group = f"/aws/lambda/{name}"
    ctx.on_cleanup(lambda: _reap_log_group(logs, group))  # before create: LIFO runs it after delete
    deadline = time.monotonic() + 90.0
    while True:
        try:
            lam.create_function(
                FunctionName=name, Runtime=_RUNTIME, Role=role_arn, Handler="bootstrap",
                Code={"ZipFile": _zip_bootstrap(_BOOTSTRAP)}, MemorySize=memory_mb, Timeout=30,
                EphemeralStorage={"Size": ephemeral_mb}, Tags={"sim2real": CHECK},
            )
            break
        except ClientError as exc:
            msg = exc.response["Error"].get("Message", "")
            if exc.response["Error"]["Code"] != "InvalidParameterValueException" or _ROLE_PROPAGATION not in msg:
                raise
            if time.monotonic() > deadline:
                raise AssertionError(f"CreateFunction({name}) kept failing on role propagation: {msg}")
            time.sleep(3)
    ctx.on_cleanup(_teardown(lambda n=name: lam.delete_function(FunctionName=n), "ResourceNotFoundException"))
    _wait_active(lam, name)
    return name


def _invoke_with_report(lam, name: str) -> tuple[dict, dict]:
    resp = lam.invoke(FunctionName=name, Payload=b"{}", LogType="Tail")
    raw = resp["Payload"].read()
    assert not resp.get("FunctionError"), f"{name} FunctionError={resp.get('FunctionError')!r}: {raw[:300]!r}"
    body = json.loads(raw)
    tail = base64.b64decode(resp["LogResult"]).decode("utf-8")
    m = _REPORT_RE.search(tail)
    assert m, f"{name}: no REPORT line with the documented fields in the invoke tail: {tail!r}"
    return body, m.groupdict()


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """On provided.al2023, a bootstrap that only speaks the Runtime API over curl sees the same
    execution-environment contract a managed runtime does: the configured MemorySize, a /tmp
    capacity that tracks EphemeralStorage.Size, and the platform's own REPORT line.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/configuration-memory.html
    Reference: https://docs.aws.amazon.com/lambda/latest/dg/configuration-ephemeral-storage.html
    Reference: https://docs.aws.amazon.com/lambda/latest/dg/runtimes-custom.html
    """
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    role_arn = _make_role(ctx)

    fn_large = _create_function(ctx, lam, logs, role_arn, ephemeral_mb=_LARGE_EPHEMERAL_MB, memory_mb=_MEMORY_MB)
    fn_small = _create_function(ctx, lam, logs, role_arn, ephemeral_mb=_SMALL_EPHEMERAL_MB, memory_mb=_MEMORY_MB)

    body_large, report_large = _invoke_with_report(lam, fn_large)
    body_small, _report_small = _invoke_with_report(lam, fn_small)

    assert body_large["memMb"] == _MEMORY_MB, (
        f"$AWS_LAMBDA_FUNCTION_MEMORY_SIZE was {body_large['memMb']!r}, "
        f"expected the configured {_MEMORY_MB}"
    )
    assert body_large["tmpTotalMb"] >= 900, (
        f"EphemeralStorage.Size={_LARGE_EPHEMERAL_MB} should report /tmp capacity near it, "
        f"got {body_large['tmpTotalMb']}MB"
    )
    assert body_small["tmpTotalMb"] < 600, (
        f"EphemeralStorage.Size={_SMALL_EPHEMERAL_MB} should report a correspondingly smaller "
        f"/tmp capacity, got {body_small['tmpTotalMb']}MB"
    )
    assert body_large["tmpTotalMb"] > body_small["tmpTotalMb"] + 300, (
        f"the large-ephemeral function must report substantially more /tmp capacity than the "
        f"small one: large={body_large['tmpTotalMb']}MB small={body_small['tmpTotalMb']}MB"
    )

    assert int(report_large["mem"]) == _MEMORY_MB, (
        f"REPORT Memory Size was {report_large['mem']} MB, expected the configured {_MEMORY_MB}"
    )
    duration = float(report_large["dur"])
    billed = int(report_large["billed"])
    max_used = int(report_large["maxmem"])
    assert duration > 0.0, f"REPORT Duration must be positive, got {report_large['dur']!r}"
    assert billed >= duration, f"Billed Duration {billed}ms must not be below Duration {duration}ms"
    assert 0 < max_used <= _MEMORY_MB, (
        f"Max Memory Used {max_used}MB must be positive and within Memory Size {_MEMORY_MB}MB"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
