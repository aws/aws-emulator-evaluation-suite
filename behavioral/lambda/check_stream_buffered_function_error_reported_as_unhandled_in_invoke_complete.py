"""stream-buffered-function-error-reported-as-unhandled-in-invoke-complete."""

from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stream-buffered-function-error-reported-as-unhandled-in-invoke-complete"
GROUP = "response_stream"
SERVICES = ["lambda"]

RUNTIME = "python3.12"
FILENAME = "index.py"
TIMEOUT_S = 10

HANDLER = """
def handler(event, context):
    if event.get("raise"):
        raise ValueError("sim2real-stream-failure")
    return {"echo": event, "version": context.function_version}
"""


def _stream(lam, **kwargs) -> dict:
    """InvokeWithResponseStream, decoded: the response fields and the ordered event list."""
    resp = lam.invoke_with_response_stream(**kwargs)
    events = []
    for event in resp["EventStream"]:
        if "PayloadChunk" in event:
            events.append(("chunk", event["PayloadChunk"]["Payload"]))
        elif "InvokeComplete" in event:
            events.append(("complete", event["InvokeComplete"]))
        else:
            events.append(("other", event))
    return {"status": resp["StatusCode"], "executed": resp.get("ExecutedVersion"),
            "events": events}


_BASIC_EXEC = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
_ROLE_PROPAGATION = "cannot be assumed by Lambda"


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


def _reap_log_group(logs, name: str, *, reads: int = 3, interval_s: float = 4.0,
                    budget_s: float = 40.0) -> None:
    """Delete log group ``name`` until ``reads`` consecutive reads find it absent; raise if not."""
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
            if time.monotonic() > deadline:
                raise AssertionError(
                    f"log group still present after {budget_s}s of deletes; {absent} clean reads"
                )
            time.sleep(interval_s)


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str):
    """Bounded retry on an observable condition. RAISES on timeout, never returns its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


def _zip(filename: str, source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, source)
    return buf.getvalue()


def _make_role(ctx, iam) -> str:
    """This check's own execution role (basic logging only), deleted in its teardown."""
    name = ctx.unique_name("sim2real-behav-url-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    iam.attach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC)
    ctx.on_cleanup(_teardown(
        lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC), "NoSuchEntity"))
    # IAM propagation exposes no pollable condition: CreateFunction retries the documented
    # role-propagation refusal instead of sleeping here.
    return role["Role"]["Arn"]


def _create_function(ctx, lam, logs, **kwargs) -> str:
    """CreateFunction retrying ONLY the role-propagation refusal; waits for Active."""
    name = kwargs["FunctionName"]
    # Registered BEFORE the function exists, so LIFO runs it AFTER delete_function.
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{name}"))
    deadline = time.monotonic() + 90.0
    while True:
        try:
            lam.create_function(**kwargs)
            break
        except ClientError as exc:
            msg = exc.response["Error"].get("Message", "")
            if exc.response["Error"]["Code"] != "InvalidParameterValueException" or (
                _ROLE_PROPAGATION not in msg
            ):
                raise
            if time.monotonic() > deadline:
                raise AssertionError(f"CreateFunction kept failing on role propagation: {msg}")
            time.sleep(3)
    ctx.on_cleanup(_teardown(
        lambda: lam.delete_function(FunctionName=name), "ResourceNotFoundException"))

    def _probe():
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg.get("State") == "Failed" or cfg.get("LastUpdateStatus") == "Failed":
            raise AssertionError(
                f"function failed: {cfg.get('StateReason')} {cfg.get('LastUpdateStatusReason')}"
            )
        return cfg

    _poll_until(
        _probe,
        lambda cfg: cfg.get("State") == "Active"
        and cfg.get("LastUpdateStatus") in (None, "Successful"),
        timeout_s=180.0, interval_s=1.0, description="the function reaching State=Active",
    )
    return name


@tags("axis:happy-path", "cap:c3", "cap:c6", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A raising Python handler invoked via InvokeWithResponseStream answers 200 with one PayloadChunk
    holding the error object (errorType, errorMessage) and an InvokeComplete with
    ErrorCode="Unhandled"; a non-raising invoke's InvokeComplete has no ErrorCode.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/API_InvokeWithResponseStream.html
    """
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    fn = _create_function(
        ctx, lam, logs,
        FunctionName=ctx.unique_name("sim2real-behav-url-"),
        Runtime=RUNTIME, Role=_make_role(ctx, ctx.client("iam")), Handler="index.handler",
        Code={"ZipFile": _zip(FILENAME, HANDLER)}, MemorySize=256, Timeout=TIMEOUT_S,
        Tags={"sim2real": CHECK},
    )
    clean = _stream(lam, FunctionName=fn, Payload=b"{}")
    assert [k for k, _ in clean["events"]] == ["chunk", "complete"], clean
    assert clean["events"][-1][1].get("ErrorCode") is None, (
        f"positive control: a clean invoke has no ErrorCode, got {clean['events'][-1][1]!r}"
    )

    failed = _stream(lam, FunctionName=fn, Payload=json.dumps({"raise": True}))
    assert failed["status"] == 200, f"the status line is still 200, got {failed['status']!r}"
    kinds = [kind for kind, _ in failed["events"]]
    assert kinds == ["chunk", "complete"], f"expected error chunk then InvokeComplete: {kinds!r}"
    error = json.loads(failed["events"][0][1])
    assert (error["errorType"], error["errorMessage"]) == ("ValueError", "sim2real-stream-failure"), (
        f"the chunk must be the runtime's error object, got {error!r}"
    )
    complete = failed["events"][1][1]
    assert complete.get("ErrorCode") == "Unhandled", (
        f"InvokeComplete must carry ErrorCode=Unhandled, got {complete!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
