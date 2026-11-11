"""deep-lambda-runtime-truth-stream-error-after-first-chunk-rejected-in-trailer."""
from __future__ import annotations

import base64
import io
import json
import time
import uuid
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-lambda-runtime-truth-stream-error-after-first-chunk-rejected-in-trailer"
GROUP = "response_streaming"
SERVICES = ["lambda"]

# A causal handshake instead of a clock: the handler writes chunk 1 and then BLOCKS until the
# client has acknowledged chunk 1 by tagging the function with the nonce it carried. If the
# stream were buffered until the handler returned, the client could never see chunk 1 in time,
# the handler's wait would expire, and chunk 2 would say acked=false.
_HANDLER_JS = """\
const { LambdaClient, ListTagsCommand } = require("@aws-sdk/client-lambda");
const lam = new LambdaClient({});
const ARN = process.env.SIM2REAL_FN_ARN;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

exports.handler = awslambda.streamifyResponse(async (event, stream, context) => {
  stream.write(JSON.stringify({ seq: 1, nonce: event.nonce }) + "\\n");
  let acked = false;
  const deadline = Date.now() + 60000;
  while (Date.now() < deadline) {
    try {
      const r = await lam.send(new ListTagsCommand({ Resource: ARN }));
      if ((r.Tags || {})["sim2real-ack"] === event.nonce) { acked = true; break; }
    } catch (e) { /* IAM propagation of the inline policy */ }
    await sleep(500);
  }
  stream.write(JSON.stringify({ seq: 2, acked: acked }) + "\\n");
  if (event.fail) { throw new Error("sim2real-boom-" + event.nonce); }
  stream.write(JSON.stringify({ seq: 3, done: true }) + "\\n");
  stream.end();
});
"""


_BASIC = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"


def _zip(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, body in files.items():
            zf.writestr(name, body)
    return buf.getvalue()


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


def _stream(lam, fn, fn_arn, nonce, fail):
    """Consume the event stream; ack chunk 1 the moment it is seen. Returns a trace."""
    resp = lam.invoke_with_response_stream(
        FunctionName=fn, InvocationType="RequestResponse", LogType="Tail",
        Payload=json.dumps({"nonce": nonce, "fail": fail}).encode())
    events, buf, records = [], b"", []
    for ev in resp["EventStream"]:
        if "PayloadChunk" in ev:
            idx = len(events)
            events.append(("chunk", ev["PayloadChunk"]["Payload"]))
            buf += ev["PayloadChunk"]["Payload"]
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                rec = json.loads(line)
                records.append((idx, rec))
                if rec.get("seq") == 1:
                    lam.tag_resource(Resource=fn_arn, Tags={"sim2real-ack": rec["nonce"]})
        elif "InvokeComplete" in ev:
            events.append(("complete", ev["InvokeComplete"]))
        else:
            events.append(("other", ev))
    return resp, events, records, buf


@tags("axis:rejection", "cap:c3", "cap:c6", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A mid-stream throw keeps HTTP 200 and the chunks already streamed, and is reported only in
    the single InvokeComplete trailer, whose LogResult carries "Invoke Error" with the message.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/configuration-response-streaming.html
    """
    lam = ctx.client("lambda")
    account = ctx.client("sts").get_caller_identity()["Account"]
    fn = ctx.unique_name("sim2real-behav-rt-serr-")
    fn_arn = f"arn:aws:lambda:{ctx.region}:{account}:function:{fn}"
    role_arn = _make_role(ctx, fn_arn)
    _create_function(
        ctx, lam, role_arn, fn, Runtime="nodejs22.x", Handler="index.handler",
        Code={"ZipFile": _zip({"index.js": _HANDLER_JS})}, MemorySize=256, Timeout=90,
        Environment={"Variables": {"SIM2REAL_FN_ARN": fn_arn}},
    )

    # ---- positive control: no throw, clean trailer, final chunk present ----
    ok_nonce = uuid.uuid4().hex
    ok_resp, ok_events, ok_records, _ = _stream(lam, fn, fn_arn, ok_nonce, fail=False)
    assert ok_resp["StatusCode"] == 200, ok_resp["StatusCode"]
    assert [r["seq"] for _, r in ok_records] == [1, 2, 3], f"control records {ok_records!r}"
    assert ok_events[-1][0] == "complete", f"control stream kinds {[k for k, _ in ok_events]!r}"
    assert not ok_events[-1][1].get("ErrorCode"), f"control trailer {ok_events[-1][1]!r}"

    # ---- break one thing: the handler throws after chunk 2 ----
    nonce = uuid.uuid4().hex
    resp, events, records, rest = _stream(lam, fn, fn_arn, nonce, fail=True)
    assert resp["StatusCode"] == 200, (
        f"a mid-stream throw must not change the HTTP status; got {resp['StatusCode']!r}")
    seqs = [r["seq"] for _, r in records]
    assert seqs == [1, 2], (
        f"the client must keep exactly the chunks written before the throw; got {seqs!r}")
    assert records[1][1]["acked"] is True, (
        f"chunk 1 was not delivered before the handler proceeded: {records!r}")
    kinds = [k for k, _ in events]
    assert kinds.count("complete") == 1 and kinds[-1] == "complete", (
        f"the error must arrive in exactly one final InvokeComplete; kinds={kinds!r}")
    trailer = events[-1][1]
    # ErrorCode/ErrorDetails come back empty for a mid-stream throw despite the model declaring
    # them, so the error is read from LogResult and ErrorCode is not asserted.
    tail = base64.b64decode(trailer.get("LogResult") or b"").decode("utf-8", "replace")
    err_lines = [ln for ln in tail.splitlines() if "\tERROR\t" in ln and "Invoke Error" in ln]
    assert err_lines, (
        f"the trailer's log tail records no 'ERROR ... Invoke Error' line for the throw; "
        f"tail={tail!r} trailer={trailer!r}")
    assert f"sim2real-boom-{nonce}" in err_lines[0], (
        f"the trailer's Invoke Error line does not carry the thrown message: {err_lines[0]!r}")
    assert "REPORT RequestId:" in tail, f"the trailer's log tail has no REPORT line: {tail!r}"
    ok_tail = base64.b64decode(ok_events[-1][1].get("LogResult") or b"").decode("utf-8", "replace")
    assert "Invoke Error" not in ok_tail, f"control stream logged an Invoke Error: {ok_tail!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
