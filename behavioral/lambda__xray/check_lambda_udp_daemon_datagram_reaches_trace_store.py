"""lambda-udp-daemon-datagram-reaches-trace-store."""

from __future__ import annotations

import io
import json
import re
import textwrap
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-udp-daemon-datagram-reaches-trace-store"

GROUP = "distributed-tracing"

SERVICES = ["lambda", "xray"]

# The handler writes ONE segment datagram to the address Lambda advertises in
# AWS_XRAY_DAEMON_ADDRESS, in the documented two-line framing. It authors no linkage: `trace_id`
# and `parent_id` both come out of the _X_AMZN_TRACE_ID the *runtime* handed this invocation, and
# `_X_AMZN_TRACE_ID` is per-invocation, so it is read inside the handler body, never at import.
_HANDLER = r'''
import json, os, socket, time


def _parse_trace_header(raw):
    out = {}
    for part in (raw or "").split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def lambda_handler(event, context):
    raw = os.environ.get("_X_AMZN_TRACE_ID")
    daemon = os.environ.get("AWS_XRAY_DAEMON_ADDRESS")
    hdr = _parse_trace_header(raw)
    root, parent = hdr.get("Root"), hdr.get("Parent")
    out = {"raw_trace_header": raw, "daemon": daemon, "root": root, "parent": parent,
           "sampled": hdr.get("Sampled"), "sent": False, "send_error": None}
    if not daemon or not root or not parent:
        return out
    host, _, port = daemon.partition(":")
    now = time.time()
    doc = {"id": event["sub_id"], "name": event["sub_name"], "trace_id": root,
           "parent_id": parent, "type": "subsegment",
           "start_time": now, "end_time": now + 0.01,
           "annotations": {"probe_tag": event["tag"]}}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(b'{"format":"json","version":1}\n' + json.dumps(doc).encode(),
                    (host, int(port)))
        out["sent"] = True
    except OSError as exc:
        out["send_error"] = repr(exc)
    finally:
        sock.close()
    # Let the daemon flush before the invocation (and its sandbox) is frozen.
    time.sleep(0.5)
    out["subsegment_window"] = [doc["start_time"], doc["end_time"]]
    return out
'''

_DAEMON_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+$")
_ROOT_RE = re.compile(r"^1-[0-9a-f]{8}-[0-9a-f]{24}$")
_SPAN_RE = re.compile(r"^[0-9a-f]{16}$")


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A raw UDP segment datagram written to AWS_XRAY_DAEMON_ADDRESS reaches the trace store,
    parented to the AWS::Lambda::Function segment Lambda created, and its annotation is queryable.
    """
    ctx.client("lambda")
    xray = ctx.client("xray")

    fn = _create_traced_lambda(ctx, _HANDLER)

    sub_id = "".join(f"{b:02x}" for b in bytes(_stable_bytes(fn["name"], 8)))
    sub_name = "probe-udp-subsegment"
    tag = f"f3udp{fn['name'][-12:]}"
    started = time.time()
    result = _invoke_lambda(ctx, fn["name"], {"sub_id": sub_id, "sub_name": sub_name, "tag": tag})

    assert "error" not in result, (
        f"the traced Lambda raised: {result!r} -- the datagram write must not fault the handler"
    )
    obs = result["payload"]
    assert isinstance(obs, dict), f"handler returned {obs!r}, expected a dict"

    daemon = obs.get("daemon")
    assert daemon and _DAEMON_RE.match(daemon), (
        f"AWS_XRAY_DAEMON_ADDRESS in the invocation environment was {daemon!r}; the handler "
        f"contract is <ipv4>:<port>. Environment keys the handler saw: {sorted(obs)!r}"
    )
    host, _, port = daemon.partition(":")
    assert port == "2000", f"daemon port was {port!r}, expected the documented '2000' ({daemon!r})"
    assert host.startswith("169.254.") or host.startswith("127."), (
        f"daemon host was {host!r}; the documented contract is loopback or link-local"
    )

    raw = obs.get("raw_trace_header")
    root, parent = obs.get("root"), obs.get("parent")
    assert root and _ROOT_RE.match(root), (
        f"_X_AMZN_TRACE_ID Root was {root!r} (whole header {raw!r}), expected 1-<8hex>-<24hex>"
    )
    assert parent and _SPAN_RE.match(parent), (
        f"_X_AMZN_TRACE_ID Parent was {parent!r} (whole header {raw!r}), expected 16 hex digits"
    )
    assert obs.get("sampled") == "1", (
        f"_X_AMZN_TRACE_ID Sampled was {obs.get('sampled')!r} on a Mode=Active function with no "
        f"caller header; expected '1' (whole header {raw!r})"
    )
    assert obs.get("send_error") is None, (
        f"sendto() to {daemon!r} raised {obs['send_error']!r} from inside the invocation"
    )
    assert obs.get("sent") is True, f"handler did not report a completed send: {obs!r}"

    docs = _poll_until(
        lambda: _trace_documents(xray, root),
        lambda ds: (any(d.get("id") == sub_id for d in ds)
                    and any(d.get("origin") == "AWS::Lambda::Function" and d.get("end_time")
                            for d in ds)),
        timeout_s=240.0,
        interval_s=5.0,
        description=(
            f"the UDP-submitted subsegment {sub_id!r} never reached the trace store under trace "
            f"{root!r} (or the AWS::Lambda::Function segment never completed)"
        ),
    )
    by_id = {d["id"]: d for d in docs if d.get("id")}

    sub = by_id[sub_id]
    assert sub.get("name") == sub_name, (
        f"stored subsegment name was {sub.get('name')!r}, the datagram carried {sub_name!r} -- "
        f"the datagram's body did not round-trip"
    )
    assert (sub.get("annotations") or {}).get("probe_tag") == tag, (
        f"stored annotations were {sub.get('annotations')!r}, the datagram carried "
        f"probe_tag={tag!r}"
    )
    traces = xray.batch_get_traces(TraceIds=[root])["Traces"]
    assert [t["Id"] for t in traces] == [root], (
        f"BatchGetTraces([{root!r}]) returned {[t['Id'] for t in traces]!r}; the datagram must be "
        f"filed under exactly the Root the runtime gave the handler"
    )

    fn_segs = [d for d in docs if d.get("origin") == "AWS::Lambda::Function"]
    assert len(fn_segs) == 1, (
        f"expected exactly one AWS::Lambda::Function segment, got {len(fn_segs)}: "
        f"{[d.get('id') for d in fn_segs]!r}"
    )
    fn_seg = fn_segs[0]
    assert fn_seg["id"] == parent, (
        f"the handler's Parent= was {parent!r} but the AWS::Lambda::Function segment id is "
        f"{fn_seg['id']!r} -- the out-of-band datagram is not parented to the segment the "
        f"service created"
    )
    assert _parent_of(docs, sub_id) == parent, (
        f"the stored subsegment's parent is {_parent_of(docs, sub_id)!r}, expected the "
        f"handler-observed Parent= {parent!r}"
    )

    svc_segs = [d for d in docs if d.get("origin") == "AWS::Lambda"]
    assert len(svc_segs) == 1, (
        f"expected exactly one AWS::Lambda service segment, got {len(svc_segs)}: "
        f"{[d.get('id') for d in svc_segs]!r} -- Lambda's two-segment shape collapsed"
    )
    assert fn_seg.get("parent_id") == svc_segs[0]["id"], (
        f"AWS::Lambda::Function parent_id is {fn_seg.get('parent_id')!r}, expected the "
        f"AWS::Lambda segment id {svc_segs[0]['id']!r}"
    )
    assert svc_segs[0].get("parent_id") is None, (
        f"the AWS::Lambda segment has parent_id {svc_segs[0].get('parent_id')!r}; on a direct "
        f"Invoke it is the trace root"
    )

    assert fn_seg["start_time"] - 0.001 <= sub["start_time"], (
        f"subsegment start {sub['start_time']!r} precedes its Lambda function segment start "
        f"{fn_seg['start_time']!r}"
    )
    assert sub["end_time"] <= fn_seg["end_time"] + 0.001, (
        f"subsegment end {sub['end_time']!r} outlives its Lambda function segment end "
        f"{fn_seg['end_time']!r}"
    )

    summary_ids = _poll_until(
        lambda: _summary_ids(xray, started - 120, time.time() + 60,
                             f'annotation.probe_tag = "{tag}"'),
        lambda ids: root in ids,
        timeout_s=180.0,
        interval_s=5.0,
        description=(
            f"GetTraceSummaries with FilterExpression annotation.probe_tag = {tag!r} never "
            f"returned trace {root!r} -- a UDP-delivered annotation did not become queryable"
        ),
    )
    assert summary_ids == {root}, (
        f"the annotation filter for the unique tag {tag!r} selected {sorted(summary_ids)!r}, "
        f"expected exactly {[root]!r}"
    )


_PREFIX = "sim2real-f3xray-"

_TAGS = {"sim2real:managed": "true", "sim2real:prefix": _PREFIX.rstrip("-")}


def _stable_bytes(seed: str, n: int) -> bytes:
    """A deterministic byte string derived from a unique resource name (no hashlib needed)."""
    acc = bytearray()
    val = 0
    for ch in seed:
        val = (val * 131 + ord(ch)) & 0xFFFFFFFFFFFFFFFF
    for i in range(n):
        acc.append((val >> (8 * (i % 8))) & 0xFF)
        val = (val * 6364136223846793005 + 1442695040888963407) & 0xFFFFFFFFFFFFFFFF
    return bytes(acc)


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_PREFIX}{kind}-")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result); return the final result, else raise AssertionError."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description}. Last observation: {last!r}"[:1200])


def _flatten(doc: dict, out: list) -> None:
    """Append doc and, recursively, every nested `subsegments` entry, stamping parents."""
    out.append(doc)
    for kid in doc.get("subsegments") or []:
        kid.setdefault("_container_id", doc.get("id"))
        _flatten(kid, out)


def _trace_documents(xray, trace_id: str) -> list:
    """Every segment AND nested subsegment document in one trace, flattened.

    X-Ray stores a subsegment whose parent_id names a segment it already holds *inside* that
    segment's `subsegments` array rather than as its own Segment, so a check that only reads
    `Traces[].Segments[].Document` cannot see it at all.
    """
    resp = xray.batch_get_traces(TraceIds=[trace_id])
    docs: list = []
    for trace in resp.get("Traces") or []:
        for seg in trace.get("Segments") or []:
            _flatten(json.loads(seg["Document"]), docs)
    return docs


def _parent_of(docs: list, doc_id: str):
    """The id this document hangs from: its explicit parent_id, else its containing segment."""
    for d in docs:
        if d.get("id") == doc_id:
            return d.get("parent_id") or d.get("_container_id")
    return None


def _summary_ids(xray, start: float, end: float, expression: str | None = None) -> set:
    """Paginated GetTraceSummaries over a window, reading every page."""
    kwargs: dict[str, Any] = {"StartTime": start, "EndTime": end}
    if expression:
        kwargs["FilterExpression"] = expression
    ids = set()
    token = None
    while True:
        if token:
            kwargs["NextToken"] = token
        resp = xray.get_trace_summaries(**kwargs)
        ids.update(s["Id"] for s in resp.get("TraceSummaries") or [])
        token = resp.get("NextToken")
        if not token:
            return ids


def _delete_role(ctx, role_name: str) -> None:
    """IAM roles need every attached + inline policy removed before deletion."""
    iam = ctx.client("iam")
    try:
        for p in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    iam.delete_role(RoleName=role_name)


def _create_role(ctx, trust_service: str, statements: list) -> dict:
    """Create an IAM role with an inline policy and register its teardown."""
    iam = ctx.client("iam")
    role_name = _xname(ctx, "role")
    trust = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": trust_service},
         "Action": "sts:AssumeRole"}]}
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
                           Path="/sim2real/",
                           Tags=[{"Key": k, "Value": v} for k, v in _TAGS.items()])
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.put_role_policy(RoleName=role_name, PolicyName="inline",
                        PolicyDocument=json.dumps({"Version": "2012-10-17",
                                                   "Statement": statements}))
    # IAM exposes no condition reporting that a role has become assumable, so there is nothing to
    # poll here; the bounded create_function retry in _create_traced_lambda is what makes waiting
    # for propagation correct, not a fixed pause here.
    return {"name": role_name, "arn": resp["Role"]["Arn"]}


def _create_traced_lambda(ctx, handler_code: str, extra_statements=None,
                          env=None, timeout=30, memory=256) -> dict:
    """A Mode=Active Lambda on a role that really can emit segments.

    Active tracing on a role without xray:PutTraceSegments emits nothing, silently, so the check
    builds its own role.
    """
    statements = [
        {"Effect": "Allow",
         "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
         "Resource": "arn:aws:logs:*:*:*"},
        {"Effect": "Allow",
         "Action": ["xray:PutTraceSegments", "xray:PutTelemetryRecords"],
         "Resource": "*"},
    ]
    statements.extend(extra_statements or [])
    role = _create_role(ctx, "lambda.amazonaws.com", statements)

    name = _xname(ctx, "fn")
    lam = ctx.client("lambda")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", textwrap.dedent(handler_code))
    kwargs: dict[str, Any] = {
        "FunctionName": name, "Runtime": "python3.12", "Role": role["arn"],
        "Handler": "lambda_function.lambda_handler", "Code": {"ZipFile": buf.getvalue()},
        "Timeout": timeout, "MemorySize": memory,
        "TracingConfig": {"Mode": "Active"}, "Tags": dict(_TAGS),
    }
    if env:
        kwargs["Environment"] = {"Variables": env}
    deadline = time.monotonic() + 60
    last_err = None
    resp = None
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(**kwargs)
            break
        except ClientError as exc:
            if "cannot be assumed" in str(exc) or "InvalidParameterValue" in str(exc):
                last_err = exc
                time.sleep(3)
                continue
            raise
    assert resp is not None, f"create_function never succeeded through IAM propagation: {last_err!r}"
    # /aws/lambda/<name> is created by the SERVICE, asynchronously, on first invoke, and survives
    # the function. Registered BEFORE the function delete so LIFO runs it AFTER: a group that
    # materialises late still gets deleted, whereas the other order loses the race and leaks it.
    ctx.on_cleanup(lambda: ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{name}"))
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    cfg = _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda r: r.get("State") == "Active",
        timeout_s=120.0, interval_s=2.0, description=f"Lambda {name} never became Active",
    )
    assert cfg.get("TracingConfig", {}).get("Mode") == "Active", (
        f"function reports TracingConfig {cfg.get('TracingConfig')!r}, expected Mode=Active"
    )
    return {"name": name, "arn": resp["FunctionArn"], "role": role}


def _invoke_lambda(ctx, name: str, payload: dict | None = None) -> dict:
    """Invoke synchronously; return {status_code[, error], payload|payload_raw}."""
    resp = ctx.client("lambda").invoke(FunctionName=name, InvocationType="RequestResponse",
                                       Payload=json.dumps(payload or {}).encode())
    body = resp["Payload"].read()
    out: dict[str, Any] = {"status_code": resp["StatusCode"]}
    if resp.get("FunctionError"):
        out["error"] = resp["FunctionError"]
    try:
        out["payload"] = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        out["payload_raw"] = body.decode("utf-8", errors="replace")
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
