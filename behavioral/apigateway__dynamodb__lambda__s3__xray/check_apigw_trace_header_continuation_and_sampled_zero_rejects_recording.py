"""apigw-trace-header-continuation-and-sampled-zero-rejects-recording."""

from __future__ import annotations

import io
import json
import re
import secrets
import textwrap
import time
import urllib.error
import urllib.request
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "apigw-trace-header-continuation-and-sampled-zero-rejects-recording"

GROUP = "distributed-tracing"

SERVICES = ["apigateway", "dynamodb", "lambda", "s3", "xray"]

# Echoes the trace context the runtime gave it and does real work on two data planes, so
# continuation is observable two hops past the edge.
_HANDLER = r'''
import json, os, socket, time
import boto3

_DDB = boto3.client("dynamodb", region_name=os.environ["AWS_REGION"])
_S3 = boto3.client("s3", region_name=os.environ["AWS_REGION"])
TBL = os.environ["PROBE_TABLE"]
BKT = os.environ["PROBE_BUCKET"]


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
    q = event.get("queryStringParameters") or {}
    key = q.get("k", "probe")

    t0 = time.time()
    put_item = _DDB.put_item(TableName=TBL, Item={"pk": {"S": key},
                                                  "root": {"S": root or "none"}})
    t1 = time.time()
    _S3.put_object(Bucket=BKT, Key=key + ".txt", Body=(root or "none").encode())
    ddb_rid = put_item["ResponseMetadata"]["RequestId"]

    sent = False
    if daemon and root and parent and q.get("sub_id"):
        host, _, port = daemon.partition(":")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.sendto(b'{"format":"json","version":1}\n' + json.dumps(
                {"id": q["sub_id"], "name": "DynamoDB", "trace_id": root, "parent_id": parent,
                 "type": "subsegment", "namespace": "aws", "start_time": t0, "end_time": t1,
                 "aws": {"operation": "PutItem", "table_name": TBL,
                         "request_id": ddb_rid}}).encode(), (host, int(port)))
            sent = True
        finally:
            sock.close()
        time.sleep(0.5)
    return {"statusCode": 200, "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"raw_trace_header": raw, "daemon": daemon, "root": root,
                                "parent": parent, "sampled": hdr.get("Sampled"),
                                "ddb_request_id": ddb_rid, "item_key": key, "sent": sent})}
'''

_ROOT_RE = re.compile(r"^1-[0-9a-f]{8}-[0-9a-f]{24}$")
_SPAN_RE = re.compile(r"^[0-9a-f]{16}$")


def _mint_root() -> str:
    """A syntactically valid, never-before-used X-Ray trace id with a current epoch prefix."""
    return f"1-{int(time.time()):08x}-{secrets.token_hex(12)}"


@tags("axis:negative-delivery", "cap:c3", "concern:data-plane", "concern:e2e",
      "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A caller-supplied `Root=` is continued through API Gateway and Lambda, and `Sampled=0` on an
    otherwise identical request records nothing while the request still does its work.

    Reference: https://docs.aws.amazon.com/xray/latest/devguide/xray-services-apigateway.html
    """
    xray = ctx.client("xray")
    ddb = ctx.client("dynamodb")
    table = _create_table(ctx)
    bucket = _create_bucket(ctx)
    fn = _create_traced_lambda(
        ctx, _HANDLER,
        extra_statements=[
            {"Effect": "Allow", "Action": ["dynamodb:PutItem"],
             "Resource": f"arn:aws:dynamodb:{ctx.region}:*:table/{table}"},
            {"Effect": "Allow", "Action": ["s3:PutObject"], "Resource": f"arn:aws:s3:::{bucket}/*"},
        ],
        env={"PROBE_TABLE": table, "PROBE_BUCKET": bucket},
    )
    api_id = _deploy_proxy_api(ctx, fn, "x", [("traced", True)])
    url = _apigw_url(ctx, api_id, "traced", "/x")
    sub_id = "".join(f"{b:02x}" for b in _stable_bytes(fn["name"] + "-sub", 8))

    window_start = time.time() - 120
    a_id, b_id = _mint_root(), _mint_root()
    assert a_id != b_id, f"the two minted trace ids collided at {a_id!r}"

    obs_a = _get_stage_json(f"{url}?k=arm-a&sub_id={sub_id}",
                            {"X-Amzn-Trace-Id": f"Root={a_id};Sampled=1"})
    obs_b = _get_stage_json(f"{url}?k=arm-b",
                            {"X-Amzn-Trace-Id": f"Root={b_id};Sampled=0"})
    obs_c = _get_stage_json(f"{url}?k=arm-c")
    obs_d = _get_stage_json(f"{url}?k=arm-d",
                            {"X-Amzn-Trace-Id": "Root=not-a-trace-id;Sampled=1"})

    assert obs_a["root"] == a_id, (
        f"the handler observed Root={obs_a['root']!r}; we supplied {a_id!r}, so the caller's "
        f"trace context was not continued (whole header {obs_a['raw_trace_header']!r})"
    )
    assert obs_a["parent"] and _SPAN_RE.match(obs_a["parent"]), (
        f"the continued request's Parent= was {obs_a['parent']!r}; the edge must mint a 16-hex "
        f"span id under our root (we sent no Parent at all)"
    )
    assert obs_a["sampled"] == "1", (
        f"the handler observed Sampled={obs_a['sampled']!r} on a Sampled=1 request"
    )

    docs_a = _poll_until(
        lambda: _trace_documents(xray, a_id),
        lambda ds: ({"AWS::ApiGateway::Stage", "AWS::Lambda::Function"} <= _origins(ds)
                    and sub_id in {d.get("id") for d in ds}),
        timeout_s=_budget_s(ctx, 240.0),
        interval_s=1.0,
        description=(
            f"the caller-supplied trace id {a_id!r} never produced an API Gateway stage "
            f"segment, a Lambda function segment and the handler's own subsegment {sub_id!r}"
        ),
        ctx=ctx,
    )
    traces_a = xray.batch_get_traces(TraceIds=[a_id])["Traces"]
    assert [t["Id"] for t in traces_a] == [a_id], (
        f"BatchGetTraces([{a_id!r}]) returned {[t['Id'] for t in traces_a]!r}; the trace must be "
        f"filed under the id WE minted, not a shadow id"
    )
    assert sub_id in {d.get("id") for d in docs_a}, (
        f"the handler's own subsegment {sub_id!r} is missing from the continued trace {a_id!r}: "
        f"{sorted(d.get('id') for d in docs_a)!r} -- continuation did not reach the handler's "
        f"own emissions"
    )

    # The negative below reads this same window, so its absence cannot be ingestion lag.
    indexed = _poll_until(
        lambda: _summary_ids(xray, window_start, time.time() + 60),
        lambda ids: a_id in ids,
        timeout_s=_budget_s(ctx, 240.0),
        interval_s=1.0,
        description=f"the continued trace {a_id!r} never appeared in GetTraceSummaries",
        ctx=ctx,
    )

    assert obs_b["root"] == b_id, (
        f"the Sampled=0 request's Root was {obs_b['root']!r}, we supplied {b_id!r}"
    )
    assert obs_b["sampled"] == "0", (
        f"the handler observed Sampled={obs_b['sampled']!r}; a caller Sampled=0 must reach the "
        f"invocation environment (whole header {obs_b['raw_trace_header']!r})"
    )
    item = ddb.get_item(TableName=table, Key={"pk": {"S": obs_b["item_key"]}}).get("Item")
    assert item and item.get("root", {}).get("S") == b_id, (
        f"the unsampled request's DynamoDB item is {item!r}; an unsampled request is not a "
        f"skipped request -- it must still have written {b_id!r}"
    )

    # AWS answers an unsampled id with either `Traces: []` or a trace with empty `Segments`.
    unsampled = xray.batch_get_traces(TraceIds=[b_id])["Traces"]
    with_segments = [t["Id"] for t in unsampled if t.get("Segments")]
    assert with_segments == [], (
        f"BatchGetTraces([{b_id!r}]) returned segments for the Sampled=0 request: "
        f"{json.dumps(unsampled, default=str)[:400]}. The Sampled=1 arm {a_id!r} was already "
        f"observed complete and indexed in the same window, so this is recording, not latency"
    )
    assert _trace_documents(xray, b_id) == [], (
        f"the unsampled trace {b_id!r} holds documents: "
        f"{[(d.get('id'), d.get('origin')) for d in _trace_documents(xray, b_id)]!r}"
    )

    assert a_id in indexed, f"control lost: {a_id!r} left the summaries window {sorted(indexed)!r}"
    assert b_id not in indexed, (
        f"the unsampled trace {b_id!r} IS indexed in GetTraceSummaries over the same window that "
        f"holds the sampled {a_id!r}"
    )

    assert obs_c["root"] and _ROOT_RE.match(obs_c["root"]), (
        f"the no-header request's Root was {obs_c['root']!r}, expected 1-<8hex>-<24hex>"
    )
    assert obs_c["root"] not in (a_id, b_id), (
        f"the no-header request reused {obs_c['root']!r} from another arm"
    )
    epoch = int(obs_c["root"].split("-")[1], 16)
    assert abs(epoch - time.time()) < 300, (
        f"the generated trace id's epoch prefix decodes to {epoch!r}, which is not within 300s "
        f"of now -- the edge returned a constant rather than a timestamped id"
    )

    # API Gateway ignores a malformed Root= and generates its own id rather than failing.
    assert obs_d["root"] and _ROOT_RE.match(obs_d["root"]), (
        f"after a malformed inbound Root the handler saw {obs_d['root']!r}; a bad context must be "
        f"replaced with a server-generated id, not propagated and not fatal"
    )
    assert obs_d["root"] not in (a_id, b_id, obs_c["root"]), (
        f"the malformed-header request reused {obs_d['root']!r} from another arm"
    )
    assert obs_d["sampled"] == "1", (
        f"the malformed-header request observed Sampled={obs_d['sampled']!r}"
    )

    final = _trace_documents(xray, a_id)
    assert {"AWS::ApiGateway::Stage", "AWS::Lambda", "AWS::Lambda::Function"} <= _origins(final), (
        f"after the negative arms the continued trace {a_id!r} holds only "
        f"{sorted(_origins(final))!r}"
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


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition", ctx=None):
    """Poll probe() until predicate(result); return the final result, else raise AssertionError."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
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
    """Paginated GetTraceSummaries over a window; other traces may share it, so read every page."""
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
    # create_function retry below is the actual wait for propagation, with a stated deadline.
    return {"name": role_name, "arn": resp["Role"]["Arn"]}


def _create_traced_lambda(ctx, handler_code: str, extra_statements=None,
                          env=None, timeout=30, memory=256) -> dict:
    """A Mode=Active Lambda on its own role granting xray:PutTraceSegments.

    Active tracing on a role without that permission silently emits nothing.
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


def _http_get(url: str, headers: dict | None = None) -> tuple:
    """GET url; return (status, body). An HTTP error status is a result, not an exception."""
    req = urllib.request.Request(url, method="GET", headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


def _apigw_url(ctx, api_id: str, stage: str, path: str) -> str:
    """The stage's invoke URL: the real-AWS execute-api host, or the emulator's user-request path."""
    return f"{ctx.rest_api_url(api_id, stage)}/{path.lstrip('/')}"


def _handler_body(status: int, body: str) -> dict:
    """The JSON object the proxy handler returned, unwrapped from the proxy envelope."""
    assert status == 200, f"the API Gateway stage returned {status}: {body[:400]!r}"
    outer = json.loads(body)
    inner = outer.get("body", outer) if isinstance(outer, dict) else outer
    return json.loads(inner) if isinstance(inner, str) else inner


def _get_stage_json(url: str, headers: dict | None = None) -> dict:
    """GET a freshly deployed stage and return the handler's JSON, retrying only 5xx/403.

    A new stage and its `lambda:AddPermission` propagate with no pollable condition; the retry is
    bounded and the final attempt still requires a 200.
    """
    seen = []
    deadline = time.monotonic() + 90
    status, body = 0, ""
    while time.monotonic() < deadline:
        status, body = _http_get(url, headers)
        if status == 200:
            return _handler_body(status, body)
        seen.append((status, body[:120]))
        if status not in (403, 429, 500, 502, 503, 504):
            break
        time.sleep(3)
    raise AssertionError(
        f"the API Gateway stage never served {url!r} with headers {headers!r}: last status "
        f"{status} body {body[:300]!r}; attempts were {seen[:6]!r}"
    )


def _create_table(ctx) -> str:
    """An on-demand DynamoDB table with one S hash key, waited to ACTIVE."""
    ddb = ctx.client("dynamodb")
    name = _xname(ctx, "tbl")
    ddb.create_table(TableName=name, BillingMode="PAY_PER_REQUEST",
                     KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
                     AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
                     Tags=[{"Key": k, "Value": v} for k, v in _TAGS.items()])
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name,
                                        WaiterConfig={"Delay": 2, "MaxAttempts": 60})
    return name


def _create_bucket(ctx) -> str:
    """A default-settings bucket whose cleanup empties it first (paginated)."""
    s3 = ctx.client("s3")
    name = _xname(ctx, "bkt")
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        # us-east-1 is CreateBucket's implicit default: the API rejects an explicit
        # LocationConstraint naming it, so the constraint is only passed for every OTHER region.
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def _drop() -> None:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=name):
            for obj in page.get("Contents") or []:
                s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_drop)
    return name


def _deploy_proxy_api(ctx, fn: dict, path_part: str, stages: list) -> str:
    """A REST API with one AWS_PROXY GET resource, deployed to each (stage, tracing) pair."""
    ag = ctx.client("apigateway")
    lam = ctx.client("lambda")
    api = ag.create_rest_api(name=_xname(ctx, "api"),
                             tags=dict(_TAGS))
    api_id = api["id"]
    ctx.on_cleanup(lambda: ag.delete_rest_api(restApiId=api_id))
    root_id = next(i["id"] for i in ag.get_resources(restApiId=api_id)["items"]
                   if i["path"] == "/")
    res = ag.create_resource(restApiId=api_id, parentId=root_id, pathPart=path_part)
    ag.put_method(restApiId=api_id, resourceId=res["id"], httpMethod="GET",
                  authorizationType="NONE")
    ag.put_integration(
        restApiId=api_id, resourceId=res["id"], httpMethod="GET", type="AWS_PROXY",
        integrationHttpMethod="POST",
        uri=(f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/"
             f"{fn['arn']}/invocations"),
    )
    account = ctx.client("sts").get_caller_identity()["Account"]
    lam.add_permission(FunctionName=fn["name"], StatementId="apigw-invoke",
                       Action="lambda:InvokeFunction",
                       Principal="apigateway.amazonaws.com",
                       SourceArn=(f"arn:aws:execute-api:{ctx.region}:{account}:"
                                  f"{api_id}/*/GET/{path_part}"))
    for stage, tracing in stages:
        ag.create_deployment(restApiId=api_id, stageName=stage)
        if tracing:
            ag.update_stage(restApiId=api_id, stageName=stage, patchOperations=[
                {"op": "replace", "path": "/tracingEnabled", "value": "true"}])
        got = ag.get_stage(restApiId=api_id, stageName=stage).get("tracingEnabled", False)
        assert bool(got) is bool(tracing), (
            f"stage {stage!r} reports tracingEnabled={got!r}, asked for {tracing!r}"
        )
    return api_id


def _origins(docs: list) -> set:
    """Every `origin` present in a flattened trace."""
    return {d.get("origin") for d in docs if d.get("origin")}


def _edge_parent(doc: dict):
    """The id this document hangs from: explicit parent_id, else its containing segment."""
    return doc.get("parent_id") or doc.get("_container_id")


def _one(docs: list, origin: str) -> dict:
    """The single document with this origin; assert there is exactly one."""
    hits = [d for d in docs if d.get("origin") == origin]
    assert len(hits) == 1, (
        f"expected exactly one {origin} document, got "
        f"{[(d.get('id'), d.get('name')) for d in hits]!r}"
    )
    return hits[0]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
