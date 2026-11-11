"""deep-lambda-runtime-truth-async-payload-band-delivered-intact-over-1mb-rejected."""
from __future__ import annotations

import hashlib
import io
import json
import time
import uuid
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-lambda-runtime-truth-async-payload-band-delivered-intact-over-1mb-rejected"
GROUP = "payload_limits"
SERVICES = ["lambda"]

_LEGACY_ASYNC = 256 * 1024     # the former 256 KB async payload ceiling
_ASYNC_LIMIT = 1024 * 1024     # documented fixed async (Event) payload ceiling, not a quota

# The async handler reports what it RECEIVED -- length and sha256 of the pad -- by tagging its
# own function, the only channel back from an Event invocation that stays inside Lambda.
_HANDLER = """\
import hashlib
import os
import time

import boto3

LAM = boto3.client("lambda")


def handler(event, context):
    pad = event.get("pad", "")
    value = "%d:%s" % (len(pad), hashlib.sha256(pad.encode()).hexdigest())
    deadline = time.time() + 40
    while True:
        try:
            LAM.tag_resource(Resource=os.environ["SIM2REAL_FN_ARN"],
                             Tags={"sim2real-got-" + event["label"]: value})
            return value
        except Exception:  # IAM propagation of the inline policy
            if time.time() > deadline:
                raise
            time.sleep(2)
"""


_BASIC = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"


def _zip(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, body in files.items():
            zf.writestr(name, body)
    return buf.getvalue()


def _error(fn):
    """(code, message) of the ClientError fn raises; a success raises AssertionError."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError("the call unexpectedly SUCCEEDED; a ClientError was expected")


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


def _poll_tag(lam, fn_arn, key, timeout_s=150):
    deadline = time.monotonic() + timeout_s
    seen = {}
    while time.monotonic() < deadline:
        seen = _tags(lam, fn_arn)
        if key in seen:
            return seen[key]
        time.sleep(2.0)
    raise AssertionError(f"tag {key!r} never appeared on {fn_arn} in {timeout_s}s; tags={seen!r}")


def _payload(label, pad_len):
    pad = uuid.uuid4().hex * (pad_len // 32 + 1)
    pad = pad[:pad_len]
    body = json.dumps({"label": label, "pad": pad}).encode()
    return body, f"{len(pad)}:{hashlib.sha256(pad.encode()).hexdigest()}"


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """An Event invoke of ~700 KB (over 256 KB, under 1 MB) is accepted and delivered byte-for-byte;
    one over 1 MB is refused with RequestEntityTooLargeException and never reaches the handler.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/gettingstarted-limits.html
    """
    lam = ctx.client("lambda")
    account = ctx.client("sts").get_caller_identity()["Account"]
    fn = ctx.unique_name("sim2real-behav-rt-async-")
    fn_arn = f"arn:aws:lambda:{ctx.region}:{account}:function:{fn}"
    role_arn = _make_role(ctx, fn_arn)
    _create_function(
        ctx, lam, role_arn, fn, Runtime="python3.12", Handler="index.handler",
        Code={"ZipFile": _zip({"index.py": _HANDLER})}, MemorySize=512, Timeout=60,
        Environment={"Variables": {"SIM2REAL_FN_ARN": fn_arn}},
    )
    # No retries: a failed async attempt must not produce a second, later side effect.
    lam.put_function_event_invoke_config(FunctionName=fn, MaximumRetryAttempts=0)

    # ---- positive: ~700 KB, above 256 KB and under the 1 MB ceiling ----
    band, band_want = _payload("band", 700 * 1024)
    assert _LEGACY_ASYNC < len(band) < _ASYNC_LIMIT, len(band)
    r = lam.invoke(FunctionName=fn, InvocationType="Event", Payload=band)
    assert r["StatusCode"] == 202, f"Event invoke of {len(band)} bytes returned {r['StatusCode']!r}"
    got = _poll_tag(lam, fn_arn, "sim2real-got-band")
    assert got == band_want, (
        f"the handler received a different payload than was sent: got {got!r}, "
        f"sent {band_want!r} ({len(band)} request bytes)")

    # ---- break one thing: cross the 1 MB async ceiling ----
    over, _ = _payload("over", _ASYNC_LIMIT + 16 * 1024)
    assert len(over) > _ASYNC_LIMIT, len(over)
    code, message = _error(lambda: lam.invoke(FunctionName=fn, InvocationType="Event", Payload=over))
    assert code == "RequestEntityTooLargeException", (
        f"a {len(over)}-byte Event invoke returned {code!r}, expected RequestEntityTooLargeException")
    expected = (
        f"{len(over)} byte payload is too large for the Event invocation type "
        f"(limit {_ASYNC_LIMIT} bytes)")
    assert message == expected, (
        f"a {len(over)}-byte Event invoke: expected message {expected!r}, got {message!r}")

    # ---- a later positive proves the channel is live when we look for the absent effect ----
    after, after_want = _payload("after", 300 * 1024)
    r2 = lam.invoke(FunctionName=fn, InvocationType="Event", Payload=after)
    assert r2["StatusCode"] == 202, r2["StatusCode"]
    assert _poll_tag(lam, fn_arn, "sim2real-got-after") == after_want, "second delivery mismatch"
    final = _tags(lam, fn_arn)
    assert "sim2real-got-over" not in final, (
        f"the refused >1 MB Event payload was delivered anyway: {final.get('sim2real-got-over')!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
