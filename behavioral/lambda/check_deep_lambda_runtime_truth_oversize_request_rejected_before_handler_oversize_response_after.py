"""deep-lambda-runtime-truth-oversize-request-rejected-before-handler-oversize-response-after."""
from __future__ import annotations

import io
import json
import time
import uuid
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-lambda-runtime-truth-oversize-request-rejected-before-handler-oversize-response-after"
GROUP = "payload_limits"
SERVICES = ["lambda"]

_SYNC_LIMIT = 6 * 1024 * 1024  # documented fixed invocation-payload ceiling, not a quota

# The handler's first act is a durable side effect OUTSIDE the response: it tags its own
# function with the nonce it was handed. Only then does it build the (possibly oversize) reply.
_HANDLER = """\
import os
import time

import boto3

LAM = boto3.client("lambda")


def handler(event, context):
    arn = os.environ["SIM2REAL_FN_ARN"]
    key = "sim2real-ran-" + event["label"]
    deadline = time.time() + 40
    while True:
        try:
            LAM.tag_resource(Resource=arn, Tags={key: event["nonce"]})
            break
        except Exception as exc:  # IAM propagation of the inline policy
            if time.time() > deadline:
                return {"tag_error": repr(exc)[:300]}
            time.sleep(2)
    if event.get("reply_bytes"):
        return "x" * int(event["reply_bytes"])
    return {"label": event["label"], "tagged": True}
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


def _poll_tag(lam, fn_arn, key, timeout_s=60):
    deadline = time.monotonic() + timeout_s
    seen = {}
    while time.monotonic() < deadline:
        seen = _tags(lam, fn_arn)
        if key in seen:
            return seen[key]
        time.sleep(1.0)
    raise AssertionError(f"tag {key!r} never appeared on {fn_arn} in {timeout_s}s; tags={seen!r}")


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """An over-6 MB request is refused with RequestEntityTooLargeException before the handler runs;
    an over-6 MB response fails with Function.ResponseSizeTooLarge only after the handler ran.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/gettingstarted-limits.html
    """
    lam = ctx.client("lambda")
    account = ctx.client("sts").get_caller_identity()["Account"]
    fn = ctx.unique_name("sim2real-behav-rt-size-")
    fn_arn = f"arn:aws:lambda:{ctx.region}:{account}:function:{fn}"
    role_arn = _make_role(ctx, fn_arn)
    _create_function(
        ctx, lam, role_arn, fn, Runtime="python3.12", Handler="index.handler",
        Code={"ZipFile": _zip({"index.py": _HANDLER})}, MemorySize=1024, Timeout=90,
        Environment={"Variables": {"SIM2REAL_FN_ARN": fn_arn}},
    )

    # ---- positive control: the side-effect channel works end to end ----
    ctl_nonce = uuid.uuid4().hex
    ctl = lam.invoke(FunctionName=fn, Payload=json.dumps(
        {"label": "control", "nonce": ctl_nonce}).encode())
    ctl_body = json.loads(ctl["Payload"].read())
    assert not ctl.get("FunctionError") and ctl_body == {"label": "control", "tagged": True}, (
        f"control invoke did not complete its side effect: {ctl.get('FunctionError')!r} "
        f"{ctl_body!r}")
    assert _poll_tag(lam, fn_arn, "sim2real-ran-control") == ctl_nonce, "control tag mismatch"

    # ---- break one thing: the REQUEST exceeds 6 MB ----
    req_nonce = uuid.uuid4().hex
    big_req = json.dumps({"label": "bigreq", "nonce": req_nonce,
                          "pad": "p" * (_SYNC_LIMIT + 64 * 1024)}).encode()
    assert len(big_req) > _SYNC_LIMIT, len(big_req)
    code, message = _error(lambda: lam.invoke(FunctionName=fn, Payload=big_req))
    assert code == "RequestEntityTooLargeException", (
        f"a {len(big_req)}-byte synchronous request returned {code!r}, expected "
        f"RequestEntityTooLargeException")
    expected = f"Request must be smaller than {_SYNC_LIMIT} bytes for the InvokeFunction operation"
    assert message == expected, (
        f"a {len(big_req)}-byte synchronous request: expected message {expected!r}, got {message!r}")

    # ---- break the other thing: the RESPONSE exceeds 6 MB ----
    resp_nonce = uuid.uuid4().hex
    big = lam.invoke(FunctionName=fn, Payload=json.dumps(
        {"label": "bigresp", "nonce": resp_nonce, "reply_bytes": 7 * 1024 * 1024}).encode())
    assert big["StatusCode"] == 200, f"oversize-response invoke status {big['StatusCode']!r}"
    assert big.get("FunctionError") == "Unhandled", (
        f"oversize response FunctionError={big.get('FunctionError')!r}, expected 'Unhandled'")
    err = json.loads(big["Payload"].read())
    assert err.get("errorType") == "Function.ResponseSizeTooLarge", (
        f"oversize response errorType={err.get('errorType')!r}; body={err!r}")

    # ---- the handler DID run for the oversize response ... ----
    assert _poll_tag(lam, fn_arn, "sim2real-ran-bigresp") == resp_nonce, (
        "the oversize-response handler's side effect carries the wrong nonce")
    # ---- ... and never ran for the oversize request (read AFTER a later effect is visible) ----
    final = _tags(lam, fn_arn)
    assert "sim2real-ran-bigreq" not in final, (
        f"the refused oversize REQUEST still reached the handler: tag "
        f"{final.get('sim2real-ran-bigreq')!r} (nonce {req_nonce!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
