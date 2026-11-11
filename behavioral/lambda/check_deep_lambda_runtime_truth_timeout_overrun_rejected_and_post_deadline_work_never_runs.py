"""deep-lambda-runtime-truth-timeout-overrun-rejected-and-post-deadline-work-never-runs."""
from __future__ import annotations

import base64
import io
import json
import time
import uuid
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-lambda-runtime-truth-timeout-overrun-rejected-and-post-deadline-work-never-runs"
GROUP = "execution_environment"
SERVICES = ["lambda"]

_TIMEOUT_S = 8
_OVERRUN_SLEEP_S = 12
_WATCH_MARGIN_S = 6

# Tag BEFORE the sleep, sleep, tag AFTER. The "after" tag is work scheduled past the deadline.
_HANDLER = """\
import os
import time

import boto3

LAM = boto3.client("lambda")
ARN = os.environ["SIM2REAL_FN_ARN"]


def _tag(key, value):
    deadline = time.time() + 30
    while True:
        try:
            LAM.tag_resource(Resource=ARN, Tags={key: value})
            return
        except Exception:  # IAM propagation of the inline policy
            if time.time() > deadline:
                raise
            time.sleep(1)


def handler(event, context):
    _tag("sim2real-before-" + event["label"], event["nonce"])
    time.sleep(float(event["sleep_s"]))
    _tag("sim2real-after-" + event["label"], event["nonce"])
    return {"label": event["label"], "finished": True}
"""


_BASIC = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"


def _zip(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, body in files.items():
            zf.writestr(name, body)
    return buf.getvalue()


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _reap_log_group(ctx, group):
    """delete_function leaves /aws/lambda/<fn>, and a buffered stream can flush after the delete
    and RECREATE it: re-delete until the group stays absent for a 30 s quiet window (bounded)."""
    logs = ctx.client("logs")
    quiet = 0
    for _ in range(40):
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
            if quiet >= 15:
                return
        time.sleep(2)


def _make_role(ctx, fn_arn):
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
    self_tag = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Action": ["lambda:TagResource", "lambda:ListTags"],
        "Resource": fn_arn}]}
    iam.put_role_policy(RoleName=name, PolicyName="sim2real-self-tag",
                        PolicyDocument=json.dumps(self_tag))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="sim2real-self-tag"))
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


def _tags(lam, fn_arn):
    return lam.list_tags(Resource=fn_arn).get("Tags", {})


def _invoke_tail(lam, fn, label, nonce, sleep_s):
    resp = lam.invoke(FunctionName=fn, LogType="Tail", Payload=json.dumps(
        {"label": label, "nonce": nonce, "sleep_s": sleep_s}).encode())
    body = json.loads(resp["Payload"].read())
    tail = base64.b64decode(resp.get("LogResult") or b"").decode("utf-8", "replace")
    rid = resp["ResponseMetadata"]["RequestId"]
    return resp, body, tail, rid


def _report_line(tail, rid):
    lines = [ln for ln in tail.splitlines() if ln.startswith(f"REPORT RequestId: {rid}")]
    assert len(lines) == 1, f"expected one REPORT line for {rid!r} in the log tail:\n{tail}"
    return lines[0]


# timing:real-time — workflow: 8 s https://docs.aws.amazon.com/lambda/latest/dg/configuration-timeout.html
@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A handler overrunning Timeout fails with Sandbox.Timedout and REPORT "Status: timeout"; work
    done before the deadline is durable and work scheduled after it never happens.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/configuration-timeout.html
    """
    lam = ctx.client("lambda")
    account = ctx.client("sts").get_caller_identity()["Account"]
    fn = ctx.unique_name("sim2real-behav-rt-tmo-")
    fn_arn = f"arn:aws:lambda:{ctx.region}:{account}:function:{fn}"
    role_arn = _make_role(ctx, fn_arn)
    _create_function(
        ctx, lam, role_arn, fn, Runtime="python3.12", Handler="index.handler",
        Code={"ZipFile": _zip({"index.py": _HANDLER})}, MemorySize=256, Timeout=_TIMEOUT_S,
        Environment={"Variables": {"SIM2REAL_FN_ARN": fn_arn}},
    )

    # ---- prime: the role's inline policy must be effective inside the Timeout first ----
    # IAM propagation has no pollable condition; retry the no-sleep invoke, bounded.
    prime_s = _budget_s(ctx, 90)
    prime_deadline = time.monotonic() + prime_s
    while True:
        prime, prime_body, _, _ = _invoke_tail(lam, fn, "prime", uuid.uuid4().hex, 0)
        if not prime.get("FunctionError"):
            break
        if time.monotonic() >= prime_deadline and _budget_spent(ctx):
            raise TimeoutError("the handler to tag its own function: the run budget ended first; not graded")
        assert time.monotonic() < prime_deadline, (
            f"the handler could not tag its own function within {prime_s:.0f}s: {prime_body!r}")
        time.sleep(2)

    # ---- positive control: the same handler, no overrun, both side effects land ----
    ctl_nonce = uuid.uuid4().hex
    ctl, ctl_body, ctl_tail, ctl_rid = _invoke_tail(lam, fn, "control", ctl_nonce, 0)
    assert not ctl.get("FunctionError") and ctl_body == {"label": "control", "finished": True}, (
        f"control invoke failed: {ctl.get('FunctionError')!r} {ctl_body!r}")
    ctl_report = _report_line(ctl_tail, ctl_rid)
    assert "Status: timeout" not in ctl_report, f"control REPORT claims a timeout: {ctl_report!r}"
    t = _tags(lam, fn_arn)
    assert t.get("sim2real-before-control") == ctl_nonce, f"control before-tag missing: {t!r}"
    assert t.get("sim2real-after-control") == ctl_nonce, f"control after-tag missing: {t!r}"

    # ---- break one thing: the handler sleeps past Timeout ----
    nonce = uuid.uuid4().hex
    started = time.monotonic()
    resp, body, tail, rid = _invoke_tail(lam, fn, "overrun", nonce, _OVERRUN_SLEEP_S)
    assert resp.get("FunctionError") == "Unhandled", (
        f"overrun FunctionError={resp.get('FunctionError')!r}, expected 'Unhandled'; body={body!r}")
    assert body.get("errorType") == "Sandbox.Timedout", f"overrun errorType: {body!r}"
    want = f"Task timed out after {_TIMEOUT_S}.00 seconds"
    assert want in body.get("errorMessage", ""), (
        f"errorMessage {body.get('errorMessage')!r} does not contain {want!r}")
    assert rid in body.get("errorMessage", ""), (
        f"errorMessage {body.get('errorMessage')!r} does not name the request id {rid!r}")
    # "Task timed out after" is carried by errorMessage; the log tail has START/END/REPORT with
    # "Status: timeout" and no separate "Task timed out" line.
    report = _report_line(tail, rid)
    assert "Status: timeout" in report, f"REPORT line lacks 'Status: timeout': {report!r}"

    # ---- pre-deadline work is durable ----
    t = _tags(lam, fn_arn)
    assert t.get("sim2real-before-overrun") == nonce, (
        f"work done before the deadline is missing: {t!r}")

    # ---- post-deadline work never happens: watch past the moment it would have ----
    watch_until = started + _OVERRUN_SLEEP_S + _WATCH_MARGIN_S
    while time.monotonic() < watch_until:
        t = _tags(lam, fn_arn)
        assert "sim2real-after-overrun" not in t, (
            f"the handler kept running past its {_TIMEOUT_S}s Timeout and did its post-deadline "
            f"work: {t.get('sim2real-after-overrun')!r}")
        time.sleep(1.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
