"""lambda-udp-daemon-malformed-framing-datagram-rejected."""

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

CHECK = "lambda-udp-daemon-malformed-framing-datagram-rejected"

GROUP = "distributed-tracing"

SERVICES = ["lambda", "xray"]

# One socket, two datagrams, ONE thing broken: the first datagram's header line says
# {"format":"garbage"} instead of {"format":"json","version":1}. Its segment body is otherwise
# valid and carries its own id, name and annotation, so if the daemon accepted it the difference
# would be visible. The second datagram is the positive control on the same socket.
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
           "sampled": hdr.get("Sampled"), "bad_error": None, "good_error": None,
           "bad_sent": False, "good_sent": False}
    if not daemon or not root or not parent:
        return out
    host, _, port = daemon.partition(":")
    now = time.time()

    def _doc(seg_id, name, tag):
        return {"id": seg_id, "name": name, "trace_id": root, "parent_id": parent,
                "type": "subsegment", "start_time": now, "end_time": now + 0.01,
                "annotations": {"probe_tag": tag}}

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # The broken one goes FIRST, on purpose: if the daemon closed or desynced on it, the
        # well-formed one behind it would be lost too, and the control below would fail.
        try:
            sock.sendto(
                b'{"format":"garbage"}\n'
                + json.dumps(_doc(event["bad_id"], event["bad_name"], event["bad_tag"])).encode(),
                (host, int(port)))
            out["bad_sent"] = True
        except OSError as exc:
            out["bad_error"] = repr(exc)
        try:
            sock.sendto(
                b'{"format":"json","version":1}\n'
                + json.dumps(_doc(event["good_id"], event["good_name"],
                                  event["good_tag"])).encode(),
                (host, int(port)))
            out["good_sent"] = True
        except OSError as exc:
            out["good_error"] = repr(exc)
    finally:
        sock.close()
    time.sleep(0.5)
    return out
'''

_DAEMON_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+$")
_ROOT_RE = re.compile(r"^1-[0-9a-f]{8}-[0-9a-f]{24}$")
_SPAN_RE = re.compile(r"^[0-9a-f]{16}$")


@tags("axis:negative-delivery", "cap:c3", "concern:data-plane", "concern:negative-classes",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A daemon datagram whose framing header line is not {"format":"json","version":1} is silently
    dropped, and dropping it does not cost the well-formed datagram sent behind it on the same
    socket; UDP returns nothing, so both outcomes are read from the trace store.
    """
    xray = ctx.client("xray")
    fn = _create_traced_lambda(ctx, _HANDLER)

    seed = fn["name"]
    good_id = "".join(f"{b:02x}" for b in _stable_bytes(seed + "-good", 8))
    bad_id = "".join(f"{b:02x}" for b in _stable_bytes(seed + "-bad", 8))
    assert good_id != bad_id, f"the two subsegment ids collided at {good_id!r}"
    good_tag = f"f3ok{seed[-12:]}"
    bad_tag = f"f3bad{seed[-12:]}"
    good_name = "probe-well-formed-framing"
    bad_name = "probe-malformed-framing"

    started = time.time()
    result = _invoke_lambda(ctx, fn["name"], {
        "good_id": good_id, "good_name": good_name, "good_tag": good_tag,
        "bad_id": bad_id, "bad_name": bad_name, "bad_tag": bad_tag,
    })
    assert "error" not in result, f"the traced Lambda raised: {result!r}"
    obs = result["payload"]
    assert isinstance(obs, dict), f"handler returned {obs!r}, expected a dict"

    daemon = obs.get("daemon")
    assert daemon and _DAEMON_RE.match(daemon), (
        f"AWS_XRAY_DAEMON_ADDRESS in the invocation environment was {daemon!r}, expected "
        f"<ipv4>:<port>"
    )
    root, parent = obs.get("root"), obs.get("parent")
    assert root and _ROOT_RE.match(root), (
        f"_X_AMZN_TRACE_ID Root was {root!r} (whole header {obs.get('raw_trace_header')!r})"
    )
    assert parent and _SPAN_RE.match(parent), (
        f"_X_AMZN_TRACE_ID Parent was {parent!r} (whole header {obs.get('raw_trace_header')!r})"
    )
    assert obs.get("bad_error") is None, (
        f"sendto() of the malformed-framing datagram raised {obs['bad_error']!r}; real AWS "
        f"accepts the write and drops the datagram silently, so an emulator that makes the "
        f"socket raise changes the handler's control flow"
    )
    assert obs.get("bad_sent") is True and obs.get("good_sent") is True, (
        f"handler did not complete both sends: {obs!r}"
    )
    assert obs.get("good_error") is None, (
        f"sendto() of the well-formed datagram raised {obs['good_error']!r} after the malformed "
        f"one -- the bad datagram poisoned the socket"
    )

    # POSITIVE CONTROL, established first so the absence below cannot be 'not yet ingested'.
    docs = _poll_until(
        lambda: _trace_documents(xray, root),
        lambda ds: (any(d.get("id") == good_id for d in ds)
                    and any(d.get("origin") == "AWS::Lambda::Function" and d.get("end_time")
                            for d in ds)),
        timeout_s=240.0,
        interval_s=5.0,
        description=(
            f"the control (well-formed) datagram {good_id!r} never reached the trace store under "
            f"trace {root!r}, so the malformed one's absence proves nothing"
        ),
    )
    good = next(d for d in docs if d.get("id") == good_id)
    assert good.get("name") == good_name, (
        f"the control subsegment stored name {good.get('name')!r}, expected {good_name!r}"
    )
    assert (good.get("annotations") or {}).get("probe_tag") == good_tag, (
        f"the control subsegment stored annotations {good.get('annotations')!r}, expected "
        f"probe_tag={good_tag!r}"
    )
    assert _parent_of(docs, good_id) == parent, (
        f"the control subsegment hangs from {_parent_of(docs, good_id)!r}, expected the "
        f"handler-observed Parent= {parent!r}"
    )

    # THE ASSERTION: the malformed-framing datagram left no trace, by id and by name.
    assert bad_id not in {d.get("id") for d in docs}, (
        f"the malformed-framing datagram's subsegment {bad_id!r} IS in trace {root!r} -- the "
        f"daemon accepted a datagram whose header line was {{\"format\":\"garbage\"}}. "
        f"Documents present: {sorted(d.get('id') for d in docs)!r}"
    )
    assert bad_name not in {d.get("name") for d in docs}, (
        f"a document named {bad_name!r} IS in trace {root!r}: "
        f"{[(d.get('id'), d.get('name')) for d in docs]!r}"
    )
    assert bad_tag not in {
        (d.get("annotations") or {}).get("probe_tag") for d in docs
    }, f"the malformed datagram's annotation {bad_tag!r} IS in trace {root!r}"

    # And the same absence in the query index, again after the control is provably indexed.
    control_ids = _poll_until(
        lambda: _summary_ids(xray, started - 120, time.time() + 60,
                             f'annotation.probe_tag = "{good_tag}"'),
        lambda ids: root in ids,
        timeout_s=180.0,
        interval_s=5.0,
        description=(
            f"GetTraceSummaries for the control annotation {good_tag!r} never returned "
            f"{root!r}, so the filtered absence below would not be a fair negative"
        ),
    )
    assert control_ids == {root}, (
        f"the control annotation filter selected {sorted(control_ids)!r}, expected {[root]!r}"
    )
    dropped_ids = _summary_ids(xray, started - 120, time.time() + 60,
                               f'annotation.probe_tag = "{bad_tag}"')
    assert dropped_ids == set(), (
        f"GetTraceSummaries for the DROPPED datagram's annotation {bad_tag!r} returned "
        f"{sorted(dropped_ids)!r}; it must select nothing, and the control filter for "
        f"{good_tag!r} returning {sorted(control_ids)!r} in the same window proves the index "
        f"is live"
    )


# ===== helpers =====

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
    # IAM exposes no condition reporting that a role has become assumable; the bounded
    # create_function retry below is what makes this correct.
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
