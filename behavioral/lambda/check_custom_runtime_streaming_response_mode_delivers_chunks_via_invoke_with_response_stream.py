"""custom-runtime-streaming-response-mode-delivers-chunks-via-invoke-with-response-stream."""

from __future__ import annotations

import hashlib
import json
import time
import uuid
import zipfile
import io

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = 'custom-runtime-streaming-response-mode-delivers-chunks-via-invoke-with-response-stream'
GROUP = 'runtime_api'
SERVICES = ['lambda']

# A shell runtime implementing the streaming half of the Runtime API by hand over a raw TCP
# socket: it sets Lambda-Runtime-Function-Response-Mode: streaming and Transfer-Encoding: chunked
# on the POST to .../response and writes CHUNKS chunks, each "<i>:" plus the 32-hex nonce doubled
# to 1 MiB, so the stream (8 MiB) exceeds the 6 MB buffered-response limit.
CHUNKS = 8
BOOTSTRAP = r'''#!/bin/bash
API="$AWS_LAMBDA_RUNTIME_API"
HOST="${API%%:*}"
PORT="${API##*:}"
while true; do
  curl -sS -D /tmp/h -o /tmp/e "http://$API/2018-06-01/runtime/invocation/next"
  RID=$(grep -i '^lambda-runtime-aws-request-id:' /tmp/h | tr -d '\r' | sed 's/^[^:]*: *//')
  EVENT=$(cat /tmp/e)
  NONCE=$(printf '%s' "$EVENT" | sed -n 's/.*"nonce"[ ]*:[ ]*"\([^"]*\)".*/\1/p')
  BLOCK="$NONCE"
  while [ ${#BLOCK} -lt 1048576 ]; do BLOCK="$BLOCK$BLOCK"; done
  BLOCK="${BLOCK:0:1048576}"
  exec 3<>"/dev/tcp/$HOST/$PORT"
  {
    printf 'POST /2018-06-01/runtime/invocation/%s/response HTTP/1.1\r\n' "$RID"
    printf 'Host: %s\r\n' "$API"
    printf 'Lambda-Runtime-Function-Response-Mode: streaming\r\n'
    printf 'Transfer-Encoding: chunked\r\n'
    printf 'Connection: close\r\n\r\n'
    for i in 0 1 2 3 4 5 6 7; do
      C="$i:$BLOCK"
      printf '%x\r\n%s\r\n' "${#C}" "$C"
    done
    printf '0\r\n\r\n'
  } >&3
  timeout 20 cat <&3 >/dev/null || true
  exec 3<&- 3>&-
done
'''


def _expected(nonce: str) -> bytes:
    block = (nonce * (1048576 // len(nonce) + 1))[:1048576]
    return b"".join(f"{i}:{block}".encode() for i in range(CHUNKS))


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
    name = ctx.unique_name("sim2real-behav-strm-role-")
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


def _invoke_stream(lam, name, payload):
    """Drain InvokeWithResponseStream: (payload bytes, InvokeComplete dict)."""
    resp = lam.invoke_with_response_stream(
        FunctionName=name, Payload=json.dumps(payload).encode())
    assert resp["StatusCode"] == 200, f"{name}: StatusCode {resp['StatusCode']!r}"
    chunks = []
    complete = None
    for event in resp["EventStream"]:
        if "PayloadChunk" in event:
            chunks.append(event["PayloadChunk"]["Payload"])
        elif "InvokeComplete" in event:
            complete = event["InvokeComplete"]
    assert complete is not None, f"{name}: EventStream never carried an InvokeComplete event"
    return b"".join(chunks), complete


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A custom runtime that posts its response with Lambda-Runtime-Function-Response-Mode:
    streaming and Transfer-Encoding: chunked delivers 8 MiB, past the 6 MB buffered limit, intact
    and in order to an InvokeWithResponseStream caller. https://docs.aws.amazon.com/lambda/latest/dg/runtimes-custom.html
    """
    lam = ctx.client("lambda", config=Config(read_timeout=120))
    iam = ctx.client("iam")
    role_arn = _execution_role(ctx, iam)
    fn = ctx.unique_name("sim2real-behav-strm-")
    _create_function(
        ctx, lam, FunctionName=fn, Runtime="provided.al2023", Handler="bootstrap", Role=role_arn,
        Code={"ZipFile": _make_zip([("bootstrap", BOOTSTRAP, 0o100755)])},
        Architectures=["x86_64"], MemorySize=512, Timeout=60, Tags={"sim2real": CHECK},
    )

    # Two invokes with different nonces: each stream carries only its own bytes.
    for _ in range(2):
        nonce = uuid.uuid4().hex
        body, complete = _invoke_stream(lam, fn, {"nonce": nonce})
        expected = _expected(nonce)
        assert len(body) == len(expected) and hashlib.sha256(body).hexdigest() == hashlib.sha256(expected).hexdigest(), (
            f"the streamed payload was {len(body)} bytes (sha256 {hashlib.sha256(body).hexdigest()}), "
            f"expected {len(expected)} bytes (sha256 {hashlib.sha256(expected).hexdigest()}); head {body[:80]!r}"
        )
        assert not complete.get("ErrorCode"), (
            f"a clean stream reported InvokeComplete.ErrorCode={complete.get('ErrorCode')!r} "
            f"{complete.get('ErrorDetails')!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
