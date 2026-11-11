"""apigw-lambda-ddb-s3-trace-tree-shape."""

from __future__ import annotations

import io
import json
import re
import textwrap
import time
import urllib.error
import urllib.request
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "apigw-lambda-ddb-s3-trace-tree-shape"

GROUP = "distributed-tracing"

SERVICES = ["apigateway", "dynamodb", "lambda", "s3", "xray"]

# The handler does real work on two data planes and then describes what it did to the X-Ray
# daemon over UDP. It authors no trace id and no linkage: `trace_id` and `parent_id` both come
# from the _X_AMZN_TRACE_ID this invocation was handed, and the `request_id` in each aws block is
# the one the DynamoDB / S3 call actually returned.
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


def _send(host, port, doc):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(b'{"format":"json","version":1}\n' + json.dumps(doc).encode(),
                    (host, int(port)))
    finally:
        sock.close()


def lambda_handler(event, context):
    raw = os.environ.get("_X_AMZN_TRACE_ID")
    daemon = os.environ.get("AWS_XRAY_DAEMON_ADDRESS")
    hdr = _parse_trace_header(raw)
    root, parent = hdr.get("Root"), hdr.get("Parent")
    q = event.get("queryStringParameters") or {}

    t0 = time.time()
    put_item = _DDB.put_item(TableName=TBL,
                             Item={"pk": {"S": q.get("k", "trace-probe")},
                                   "root": {"S": root or "none"}})
    t1 = time.time()
    put_obj = _S3.put_object(Bucket=BKT, Key=q.get("k", "trace-probe") + ".txt",
                             Body=(root or "none").encode())
    t2 = time.time()
    ddb_rid = put_item["ResponseMetadata"]["RequestId"]
    s3_rid = put_obj["ResponseMetadata"]["RequestId"]

    sent = False
    if daemon and root and parent:
        host, _, port = daemon.partition(":")
        _send(host, port, {"id": q["ddb_sub_id"], "name": "DynamoDB", "trace_id": root,
                           "parent_id": parent, "type": "subsegment", "namespace": "aws",
                           "start_time": t0, "end_time": t1,
                           "aws": {"operation": "PutItem", "table_name": TBL,
                                   "request_id": ddb_rid}})
        _send(host, port, {"id": q["s3_sub_id"], "name": "S3", "trace_id": root,
                           "parent_id": parent, "type": "subsegment", "namespace": "aws",
                           "start_time": t1, "end_time": t2,
                           "aws": {"operation": "PutObject", "bucket_name": BKT,
                                   "request_id": s3_rid}})
        sent = True
        time.sleep(0.5)
    return {"statusCode": 200, "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"raw_trace_header": raw, "daemon": daemon, "root": root,
                                "parent": parent, "sampled": hdr.get("Sampled"),
                                "ddb_request_id": ddb_rid, "s3_request_id": s3_rid,
                                "sent": sent})}
'''

_HEADER_RE = re.compile(r"^Root=1-[0-9a-f]{8}-[0-9a-f]{24};Parent=[0-9a-f]{16};Sampled=1(;.*)?$")


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """One GET to a traced REST API stage yields one X-Ray trace forming a single tree across API
    Gateway, Lambda and the handler, with inferred DynamoDB and S3 nodes; an untraced stage
    yields no API Gateway segment.

    Reference: https://docs.aws.amazon.com/xray/latest/devguide/xray-services-apigateway.html
    """
    xray = ctx.client("xray")
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
    api_id = _deploy_proxy_api(ctx, fn, "x", [("traced", True), ("untraced", False)])

    ddb_sub_id = "".join(f"{b:02x}" for b in _stable_bytes(fn["name"] + "-ddb", 8))
    s3_sub_id = "".join(f"{b:02x}" for b in _stable_bytes(fn["name"] + "-s3", 8))
    assert ddb_sub_id != s3_sub_id, f"the two subsegment ids collided at {ddb_sub_id!r}"
    query = f"?ddb_sub_id={ddb_sub_id}&s3_sub_id={s3_sub_id}&k=traced-probe"

    obs = _get_stage_json(_apigw_url(ctx, api_id, "traced", "/x") + query)
    root = obs["root"]

    # 1. The context the edge stamped on the invocation is a real, well-formed, sampled one.
    assert obs["raw_trace_header"] and _HEADER_RE.match(obs["raw_trace_header"]), (
        f"_X_AMZN_TRACE_ID was {obs['raw_trace_header']!r}; expected "
        f"Root=1-<8hex>-<24hex>;Parent=<16hex>;Sampled=1"
    )
    assert obs["sent"] is True, f"the handler did not emit its subsegments: {obs!r}"

    docs = _poll_until(
        lambda: _trace_documents(xray, root),
        lambda ds: (_origins(ds) >= {"AWS::ApiGateway::Stage", "AWS::Lambda",
                                     "AWS::Lambda::Function", "AWS::DynamoDB::Table",
                                     "AWS::S3::Bucket"}
                    and all(d.get("end_time") for d in ds
                            if d.get("origin") in ("AWS::ApiGateway::Stage", "AWS::Lambda",
                                                   "AWS::Lambda::Function"))),
        timeout_s=240.0,
        interval_s=5.0,
        description=(
            f"trace {root!r} never reached the five-producer shape (API Gateway stage, Lambda "
            f"service, Lambda function, inferred DynamoDB table, inferred S3 bucket) with all "
            f"three service segments complete"
        ),
    )

    # 2. Exactly one trace, filed under the id the edge minted.
    traces = xray.batch_get_traces(TraceIds=[root])["Traces"]
    assert [t["Id"] for t in traces] == [root], (
        f"BatchGetTraces([{root!r}]) returned {[t['Id'] for t in traces]!r}, expected exactly one "
        f"trace under that id"
    )

    by_id = {d["id"]: d for d in docs if d.get("id")}
    assert len(by_id) == len(docs), (
        f"the trace holds duplicate document ids: {sorted(d.get('id') for d in docs)!r}"
    )

    # 3. Three producers, not one.
    assert _origins(docs) >= {"AWS::ApiGateway::Stage", "AWS::Lambda", "AWS::Lambda::Function"}, (
        f"trace {root!r} origins were {sorted(_origins(docs))!r}; API Gateway, the Lambda service "
        f"and the Lambda function must each have produced a segment"
    )

    # 4. The root is the edge, not the function.
    roots = [d for d in docs if _edge_parent(d) is None]
    assert len(roots) == 1, (
        f"expected exactly one root document, got "
        f"{[(d.get('id'), d.get('origin')) for d in roots]!r}"
    )
    assert roots[0].get("origin") == "AWS::ApiGateway::Stage", (
        f"the trace root has origin {roots[0].get('origin')!r}; on a traced REST API stage the "
        f"root must be AWS::ApiGateway::Stage"
    )
    assert roots[0].get("name", "").endswith("/traced"), (
        f"the stage segment is named {roots[0].get('name')!r}, expected <api>/traced"
    )

    # 5. The id graph is closed: no dangling parent.
    dangling = {d["id"]: _edge_parent(d) for d in docs
                if _edge_parent(d) is not None and _edge_parent(d) not in by_id}
    assert not dangling, (
        f"documents in trace {root!r} name parents that are not in the trace: {dangling!r}"
    )

    # 6. It is a tree: one root, n-1 edges, acyclic.
    edges = sum(1 for d in docs if _edge_parent(d) is not None)
    assert edges == len(by_id) - 1, (
        f"trace {root!r} has {len(by_id)} documents and {edges} parent edges; a tree has n-1"
    )
    for doc_id in by_id:
        seen, cur = set(), doc_id
        while cur is not None:
            assert cur not in seen, f"parent cycle through {doc_id!r} in trace {root!r}: {seen!r}"
            seen.add(cur)
            cur = _edge_parent(by_id[cur])

    # 7. Lambda's two-segment shape, and the edge -> service link through the stage subsegment.
    svc = _one(docs, "AWS::Lambda")
    fn_seg = _one(docs, "AWS::Lambda::Function")
    assert fn_seg.get("parent_id") == svc["id"], (
        f"AWS::Lambda::Function parent_id is {fn_seg.get('parent_id')!r}, expected the "
        f"AWS::Lambda segment id {svc['id']!r} -- an emulator collapsing them to one segment "
        f"fails here"
    )
    link = by_id[_edge_parent(svc)]
    assert link.get("namespace") == "aws" and link.get("name") == "Lambda", (
        f"the AWS::Lambda segment hangs from {link!r}; on real AWS its parent is the stage "
        f"segment's nested aws-namespace `Lambda` subsegment"
    )
    assert (link.get("aws") or {}).get("function_name") == fn["name"], (
        f"the stage's Lambda subsegment names function "
        f"{(link.get('aws') or {}).get('function_name')!r}, expected {fn['name']!r}"
    )
    assert link.get("_container_id") == roots[0]["id"], (
        f"that subsegment is nested under {link.get('_container_id')!r}, not under the stage "
        f"segment {roots[0]['id']!r}"
    )

    # 8/9. The handler's downstream calls are attributed to the right AWS resources, carrying the
    # request ids those calls actually returned.
    ddb_sub = by_id.get(ddb_sub_id)
    assert ddb_sub is not None, (
        f"the DynamoDB subsegment {ddb_sub_id!r} is not in trace {root!r}: "
        f"{sorted(by_id)!r}"
    )
    assert ddb_sub.get("namespace") == "aws", (
        f"the DynamoDB subsegment namespace is {ddb_sub.get('namespace')!r}, expected 'aws'"
    )
    assert (ddb_sub.get("aws") or {}).get("table_name") == table, (
        f"the DynamoDB subsegment names table {(ddb_sub.get('aws') or {}).get('table_name')!r}, "
        f"expected {table!r}"
    )
    assert (ddb_sub.get("aws") or {}).get("operation") == "PutItem", (
        f"the DynamoDB subsegment operation is "
        f"{(ddb_sub.get('aws') or {}).get('operation')!r}, expected 'PutItem'"
    )
    assert (ddb_sub.get("aws") or {}).get("request_id") == obs["ddb_request_id"], (
        f"the stored request_id is {(ddb_sub.get('aws') or {}).get('request_id')!r} but DynamoDB "
        f"returned {obs['ddb_request_id']!r} to the handler"
    )
    s3_sub = by_id.get(s3_sub_id)
    assert s3_sub is not None, (
        f"the S3 subsegment {s3_sub_id!r} is not in trace {root!r}: {sorted(by_id)!r}"
    )
    assert (s3_sub.get("aws") or {}).get("bucket_name") == bucket, (
        f"the S3 subsegment names bucket {(s3_sub.get('aws') or {}).get('bucket_name')!r}, "
        f"expected {bucket!r}"
    )
    assert (s3_sub.get("aws") or {}).get("request_id") == obs["s3_request_id"], (
        f"the stored request_id is {(s3_sub.get('aws') or {}).get('request_id')!r} but S3 "
        f"returned {obs['s3_request_id']!r} to the handler"
    )
    assert ddb_sub.get("_container_id") == fn_seg["id"], (
        f"the DynamoDB subsegment is nested under {ddb_sub.get('_container_id')!r}, expected the "
        f"Lambda function segment {fn_seg['id']!r}"
    )
    assert s3_sub.get("_container_id") == fn_seg["id"], (
        f"the S3 subsegment is nested under {s3_sub.get('_container_id')!r}, expected the Lambda "
        f"function segment {fn_seg['id']!r}"
    )

    # 10. X-Ray SYNTHESISED the two downstream resource nodes. Nothing sent them.
    ddb_node = _one(docs, "AWS::DynamoDB::Table")
    assert ddb_node.get("inferred") is True, (
        f"the AWS::DynamoDB::Table document is not marked inferred: {ddb_node!r}"
    )
    assert ddb_node.get("parent_id") == ddb_sub_id, (
        f"the inferred DynamoDB node hangs from {ddb_node.get('parent_id')!r}, expected the "
        f"handler's subsegment {ddb_sub_id!r}"
    )
    s3_node = _one(docs, "AWS::S3::Bucket")
    assert s3_node.get("inferred") is True, (
        f"the AWS::S3::Bucket document is not marked inferred: {s3_node!r}"
    )
    assert s3_node.get("parent_id") == s3_sub_id, (
        f"the inferred S3 node hangs from {s3_node.get('parent_id')!r}, expected the handler's "
        f"subsegment {s3_sub_id!r}"
    )

    # 11. Durations nest, with ~1 ms of slop where a child's end is stamped after its parent's.
    #     The stage's nested `Lambda` subsegment has zero duration and does not contain its child,
    #     so it is deliberately left out of this list.
    for child, parent_doc, label in ((fn_seg, svc, "Lambda function inside Lambda service"),
                                     (svc, roots[0], "Lambda service inside API stage"),
                                     (ddb_sub, fn_seg, "DynamoDB subsegment inside function"),
                                     (s3_sub, fn_seg, "S3 subsegment inside function")):
        assert child["start_time"] >= parent_doc["start_time"] - 0.01, (
            f"{label}: child starts {child['start_time']!r} before parent "
            f"{parent_doc['start_time']!r}"
        )
        assert child["end_time"] <= parent_doc["end_time"] + 0.01, (
            f"{label}: child ends {child['end_time']!r} after parent "
            f"{parent_doc['end_time']!r}"
        )
    serial = ((ddb_sub["end_time"] - ddb_sub["start_time"])
              + (s3_sub["end_time"] - s3_sub["start_time"]))
    root_dur = roots[0]["end_time"] - roots[0]["start_time"]
    assert root_dur >= serial, (
        f"the stage segment lasted {root_dur!r}s but the two serial downstream subsegments it "
        f"contains total {serial!r}s"
    )

    # 12. FAILURE ARM: the same request through a stage with tracingEnabled=false produces no
    #     API Gateway segment -- and the control is that Lambda's own segments still appear, so
    #     the absence is the stage setting and not a broken trace.
    obs_u = _get_stage_json(_apigw_url(ctx, api_id, "untraced", "/x")
                            + query.replace("traced-probe", "untraced-probe"))
    root_u = obs_u["root"]
    assert root_u != root, f"the untraced stage reused trace id {root_u!r}"
    docs_u = _poll_until(
        lambda: _trace_documents(xray, root_u),
        lambda ds: (_origins(ds) >= {"AWS::Lambda", "AWS::Lambda::Function"}
                    and all(d.get("end_time") for d in ds
                            if d.get("origin") in ("AWS::Lambda", "AWS::Lambda::Function"))),
        timeout_s=240.0,
        interval_s=5.0,
        description=(
            f"the untraced stage's trace {root_u!r} never produced the Lambda segments that are "
            f"this arm's positive control"
        ),
    )
    assert "AWS::ApiGateway::Stage" not in _origins(docs_u), (
        f"the stage with tracingEnabled=false still produced an AWS::ApiGateway::Stage segment "
        f"in trace {root_u!r}: {[(d.get('id'), d.get('origin')) for d in docs_u]!r}"
    )
    assert _one(docs_u, "AWS::Lambda").get("parent_id") is None, (
        f"with no edge segment the AWS::Lambda segment must be the root, but it hangs from "
        f"{_one(docs_u, 'AWS::Lambda').get('parent_id')!r}"
    )
    assert ddb_sub_id in {d.get("id") for d in docs_u}, (
        f"control failed: the handler's DynamoDB subsegment is missing from the untraced stage's "
        f"trace {root_u!r}, so its missing API Gateway segment proves nothing"
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
    """Paginated GetTraceSummaries over a window; other traces can share it, so read every page."""
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
    # create_function retry below is the actual wait -- it is what makes this correct.
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
    """The stage's invoke URL for a resource path."""
    return f"{ctx.rest_api_url(api_id, stage)}/{path.lstrip('/')}"


def _handler_body(status: int, body: str) -> dict:
    """The JSON object the proxy handler returned, unwrapped from the proxy envelope."""
    assert status == 200, f"the API Gateway stage returned {status}: {body[:400]!r}"
    outer = json.loads(body)
    inner = outer.get("body", outer) if isinstance(outer, dict) else outer
    return json.loads(inner) if isinstance(inner, str) else inner


def _get_stage_json(url: str, headers: dict | None = None) -> dict:
    """GET a freshly deployed stage and return the handler's JSON, retrying only 403/429/5xx.

    A new stage and its lambda:AddPermission propagate with no condition to poll; a 200 is still
    required once the bounded retry runs out.
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
