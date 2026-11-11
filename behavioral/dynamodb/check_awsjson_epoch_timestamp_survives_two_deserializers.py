"""awsjson-epoch-timestamp-survives-two-deserializers."""
from __future__ import annotations

import http.server
import io
import json
import threading
import time
import zipfile

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "awsjson-epoch-timestamp-survives-two-deserializers"
GROUP = 'multi-sdk-timestamp-encoding'
SERVICES = ['dynamodb']

#: Throwaway keys for the loopback servers below; the real credentials never reach them.
_LOOPBACK_CREDS = {"aws_access_key_id": "loopbackonly", "aws_secret_access_key": "loopbackonly"}

_ROLE_NOT_READY = 'The role defined for the function cannot be assumed by Lambda.'
_JS_SOURCE = r'''
import http from "node:http";
import {DynamoDBClient, DescribeTableCommand} from "@aws-sdk/client-dynamodb";
import pj from "@aws-sdk/client-dynamodb/package.json" with {type: "json"};

// Read one DescribeTable response served from loopback inside this sandbox, so the SAME
// deserializer that just read real AWS also reads the emulator-shaped variants.
const local = async (body) => {
  const srv = http.createServer((req, rep) => {
    let d = ""; req.on("data", (c) => d += c);
    req.on("end", () => {
      rep.writeHead(200, {"content-type": "application/x-amz-json-1.0"});
      rep.end(body);
    });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  // region is a required constructor field but this client only ever talks to the loopback
  // server above -- the literal never reaches a real endpoint or scopes a real resource.
  const cl = new DynamoDBClient({
    region: "us-west-2", endpoint: `http://127.0.0.1:${srv.address().port}`,
    credentials: {accessKeyId: "loopbackonly", secretAccessKey: "loopback"},
    maxAttempts: 1});
  try {
    const r = await cl.send(new DescribeTableCommand({TableName: "t"}));
    const d = r.Table.CreationDateTime;
    return {ok: true, isDate: d instanceof Date,
            iso: d instanceof Date ? d.toISOString() : String(d),
            epochMs: d instanceof Date ? d.getTime() : null};
  } catch (e) {
    return {ok: false, ctor: e.constructor.name, name: e.name,
            message: String(e.message).slice(0, 200)};
  } finally { srv.close(); }
};

export const handler = async (ev) => {
  const out = {sdkVersion: pj.version, node: process.version};
  const cl = new DynamoDBClient({region: ev.region});
  try {
    const r = await cl.send(new DescribeTableCommand({TableName: ev.table}));
    const d = r.Table.CreationDateTime;
    out.real = {ok: true, isDate: d instanceof Date, iso: d.toISOString(),
                epochMs: d.getTime(), tableStatus: r.Table.TableStatus,
                tableName: r.Table.TableName};
  } catch (e) {
    out.real = {ok: false, name: e.name, message: String(e.message).slice(0, 200)};
  }
  const mk = (v) => JSON.stringify({Table: {TableName: "t", TableStatus: "ACTIVE",
      CreationDateTime: v, ItemCount: 0, TableSizeBytes: 0}});
  out.epochFloat = await local(mk(ev.epochSeconds));
  out.numericString = await local(mk(String(ev.epochSeconds)));
  out.iso8601 = await local(mk(ev.iso8601));
  out.rfc1123 = await local(mk(ev.rfc1123));
  return out;
};
'''


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _await_table_active(ctx, ddb, table: str) -> None:
    """Poll DescribeTable every second until the table is ACTIVE, bounded by the budget."""
    deadline = time.time() + _budget_s(ctx, 300.0)
    status = None
    while True:
        try:
            status = ddb.describe_table(TableName=table)["Table"]["TableStatus"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise
        if status == "ACTIVE":
            return
        if time.time() >= deadline and _budget_spent(ctx):
            raise TimeoutError(f"table {table!r} ACTIVE: the run budget ended first; not graded")
        assert time.time() < deadline, f"table {table!r} never reached ACTIVE (last {status!r})"
        time.sleep(1.0)


def _await_function_active(ctx, lam, fn_name: str) -> None:
    """Poll GetFunctionConfiguration every second until State is Active, bounded by the budget."""
    deadline = time.time() + _budget_s(ctx, 300.0)
    while True:
        conf = lam.get_function_configuration(FunctionName=fn_name)
        state = conf.get("State")
        if state == "Active":
            return
        assert state != "Failed", f"function {fn_name!r} failed to activate: {conf.get('StateReason')!r}"
        if time.time() >= deadline and _budget_spent(ctx):
            raise TimeoutError(f"function {fn_name!r} Active: the run budget ended first; not graded")
        assert time.time() < deadline, f"function {fn_name!r} never reached Active (last {state!r})"
        time.sleep(1.0)


def _absent_ok(fn) -> None:
    """Failure-path teardown for a resource the success path deletes itself: only an
    already-absent resource is tolerated, any other failure still surfaces."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _teardown_function(ctx, lam, logs, fn_name: str) -> None:
    """Delete a function and its log group, verified. Lambda creates the group on first invoke,
    so a delete registered at create time can race it into existence; deleting inline at the
    end is the reliable order."""
    lam.delete_function(FunctionName=fn_name)
    group = f"/aws/lambda/{fn_name}"
    deadline = time.time() + _budget_s(ctx, 120.0)
    while time.time() < deadline:
        try:
            logs.delete_log_group(logGroupName=group)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise
        described = logs.describe_log_groups(logGroupNamePrefix=group)["logGroups"]
        if not [g for g in described if g["logGroupName"] == group]:
            time.sleep(2.0)
            described = logs.describe_log_groups(logGroupNamePrefix=group)["logGroups"]
            if not [g for g in described if g["logGroupName"] == group]:
                return
        time.sleep(2.0)
    if _budget_spent(ctx):
        raise TimeoutError(f"log group {group!r} deleted: the run budget ended first; not graded")
    raise AssertionError(f"log group {group!r} still present 120s after delete_log_group")


class _OneShotHandler(http.server.BaseHTTPRequestHandler):
    """Serve one canned awsJson1.0 body, so botocore's own parser reads it."""

    body = b'{}'

    def do_POST(self):  # noqa: N802 - BaseHTTPRequestHandler's contract
        self.rfile.read(int(self.headers.get("content-length") or 0))
        self.send_response(200)
        self.send_header("content-type", "application/x-amz-json-1.0")
        self.send_header("content-length", str(len(self.body)))
        self.end_headers()
        self.wfile.write(self.body)

    def log_message(self, *args):
        return


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """DescribeTable's epochSeconds CreationDateTime is a JSON number matching the create response,
    and botocore and the JS v3 SDK (which fails on string dates) read the same instant.
    """
    import urllib3

    ddb = ctx.client("dynamodb")
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]

    base = ctx.unique_name("sim2real-behav-h1ts-")
    table = base + "-t"

    created = ddb.create_table(
        TableName=table, BillingMode="PAY_PER_REQUEST",
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _absent_ok(lambda: ddb.delete_table(TableName=table)))
    create_dt = created["TableDescription"]["CreationDateTime"]
    _await_table_active(ctx, ddb, table)

    # ---- 1. the wire form: a JSON NUMBER, with sub-second precision preserved.
    raw_creds = ddb._request_signer._credentials
    frozen = (raw_creds.get_frozen_credentials()
              if hasattr(raw_creds, "get_frozen_credentials") else raw_creds)
    endpoint = ddb.meta.endpoint_url
    # The target's own TLS trust: on real AWS the system CAs, on an emulator its pinned chain.
    verify = ctx.http_verify
    pool = urllib3.PoolManager(cert_reqs="CERT_REQUIRED" if verify else "CERT_NONE",
                               ca_certs=verify if isinstance(verify, str) else None)
    payload = json.dumps({"TableName": table}).encode()
    req = AWSRequest(method="POST", url=endpoint, data=payload, headers={
        "content-type": "application/x-amz-json-1.0",
        "x-amz-target": "DynamoDB_20120810.DescribeTable"})
    SigV4Auth(frozen, "dynamodb", ctx.region).add_auth(req)
    resp = pool.request("POST", endpoint, body=payload,
                        headers=dict(req.headers.items()), retries=False)
    assert resp.status == 200, f"raw DescribeTable gave {resp.status!r}: {resp.data[:300]!r}"
    wire = json.loads(resp.data)["Table"]["CreationDateTime"]
    assert isinstance(wire, (int, float)) and not isinstance(wire, bool), (
        f"CreationDateTime is on the wire as {type(wire).__name__} {wire!r}; awsJson1.0's "
        "epochSeconds is a JSON NUMBER, and a string here is the single most common emulator "
        "timestamp bug -- botocore would accept it silently")
    assert abs(wire - create_dt.timestamp()) < 0.001, (
        f"the wire epoch {wire!r} disagrees with the create response {create_dt!r} "
        f"({create_dt.timestamp()!r})")

    # ---- 2. botocore's own read agrees to the millisecond.
    described = ddb.describe_table(TableName=table)["Table"]["CreationDateTime"]
    assert abs(described.timestamp() - create_dt.timestamp()) < 0.001, (
        f"describe_table reported {described!r}, create_table reported {create_dt!r}")
    assert described.microsecond == create_dt.microsecond, (
        f"sub-second precision changed on the round trip: {described.microsecond!r} vs "
        f"{create_dt.microsecond!r}")

    # ---- 3. botocore accepts ALL of epoch/numeric-string/ISO8601/RFC1123 for this field, so
    #         it cannot detect a wrongly-encoded timestamp on its own.
    iso8601 = "2026-09-13T12:00:00Z"
    rfc1123 = "Sat, 13 Sep 2026 12:00:00 GMT"
    expected_string_epoch = 1789300800.0  # 2026-09-13T12:00:00Z

    def _serve(value) -> object:
        body = json.dumps({"Table": {"TableName": "t", "TableStatus": "ACTIVE",
                                     "CreationDateTime": value, "ItemCount": 0,
                                     "TableSizeBytes": 0}}).encode()
        handler = type("_H", (_OneShotHandler,), {"body": body})
        server = http.server.HTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            # Loopback only, throwaway credentials: nothing here reaches AWS, so the real
            # credentials are deliberately not used and cannot leak into this client.
            client = ctx.client(
                "dynamodb", endpoint_url=f"http://127.0.0.1:{server.server_address[1]}",
                creds=_LOOPBACK_CREDS, config=Config(retries={"max_attempts": 0}))
            return client.describe_table(TableName="t")["Table"]["CreationDateTime"]
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=10.0)

    boto_epoch = _serve(create_dt.timestamp())
    assert abs(boto_epoch.timestamp() - create_dt.timestamp()) < 0.001, (
        f"botocore misread its own epoch encoding: {boto_epoch!r}")
    boto_numstr = _serve(str(create_dt.timestamp()))
    assert abs(boto_numstr.timestamp() - create_dt.timestamp()) < 0.001, (
        f"botocore read a numeric-string epoch as {boto_numstr!r}")
    boto_iso = _serve(iso8601)
    assert boto_iso.timestamp() == expected_string_epoch, (
        f"botocore read the ISO8601 string {iso8601!r} in an epochSeconds field as "
        f"{boto_iso!r} ({boto_iso.timestamp()!r}), expected {expected_string_epoch!r} -- it "
        "accepts the wrong encoding silently, which is why no botocore-graded check can catch it")
    boto_rfc = _serve(rfc1123)
    assert boto_rfc.timestamp() == expected_string_epoch, (
        f"botocore read the RFC1123 string {rfc1123!r} in an epochSeconds field as "
        f"{boto_rfc!r}, expected {expected_string_epoch!r}")

    # ------------------------------------------------------- the second deserializer, in Lambda
    role_name = base + "-role"
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                           "Principal": {"Service": "lambda.amazonaws.com"},
                           "Action": "sts:AssumeRole"}]}),
        Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(
        RoleName=role_name, PolicyName="ddb",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["dynamodb:DescribeTable"],
                           "Resource": f"arn:aws:dynamodb:{ctx.region}:{account}:table/{base}-*"},
                          {"Effect": "Allow",
                           "Action": ["logs:CreateLogGroup", "logs:CreateLogStream",
                                      "logs:PutLogEvents"], "Resource": "*"}]}))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="ddb"))

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        info = zipfile.ZipInfo("index.mjs", (2020, 1, 1, 0, 0, 0))
        info.external_attr = 0o644 << 16
        zf.writestr(info, _JS_SOURCE)

    fn_name = base + "-js"
    # IAM propagation exposes no condition to poll, so the wait is a bounded retry over
    # InvalidParameterValueException with a stated deadline, never an unconditional sleep.
    fn = None
    deadline = time.time() + _budget_s(ctx, 120.0)
    while fn is None:
        try:
            fn = lam.create_function(
                FunctionName=fn_name, Runtime="nodejs22.x", Role=role_arn,
                Handler="index.handler", Code={"ZipFile": buf.getvalue()},
                Timeout=60, MemorySize=512, Tags={"sim2real": CHECK})
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "InvalidParameterValueException" and time.time() >= deadline and _budget_spent(ctx):
                raise TimeoutError("the function's role propagating: the run budget ended first; not graded") from None
            message = exc.response.get("Error", {}).get("Message")
            assert code == "InvalidParameterValueException" and time.time() < deadline, (
                f"create_function failed with {code!r}: {exc}")
            assert message == _ROLE_NOT_READY, (
                f"create_function failed with {code!r} for a reason other than IAM "
                f"propagation: {message!r}")
            time.sleep(2.0)
    ctx.on_cleanup(lambda: _absent_ok(
        lambda: logs.delete_log_group(logGroupName=f"/aws/lambda/{fn_name}")))
    ctx.on_cleanup(lambda: _absent_ok(lambda: lam.delete_function(FunctionName=fn_name)))
    _await_function_active(ctx, lam, fn_name)

    event = json.dumps({"region": ctx.region, "table": table,
                        "epochSeconds": create_dt.timestamp(),
                        "iso8601": iso8601, "rfc1123": rfc1123}).encode()
    js = None
    deadline = time.time() + _budget_s(ctx, 180.0)
    while True:
        invoked = lam.invoke(FunctionName=fn_name, Payload=event, LogType="Tail")
        assert invoked.get("FunctionError") is None, (
            f"the JS v3 consumer failed: {invoked['Payload'].read()!r}")
        js = json.loads(invoked["Payload"].read())
        if js.get("real", {}).get("ok") is True or time.time() > deadline:
            break
        time.sleep(2.0)  # bounded retry over IAM propagation at first use of the permission
    if js["real"].get("ok") is not True and _budget_spent(ctx):
        raise TimeoutError("the JS consumer's role taking effect: the run budget ended first; not graded")
    assert js["real"].get("ok") is True, (
        f"the JS consumer never read the real table within 180s: {js!r}")

    version = js["sdkVersion"]

    # ---- 4. the two deserializers land on the same instant, to the millisecond.
    real = js["real"]
    assert real["isDate"] is True, (
        f"JS v3 {version} did not deserialize CreationDateTime into a Date: {real!r}")
    assert real["tableName"] == table and real["tableStatus"] == "ACTIVE", (
        f"the JS consumer read a different table: {real!r}")
    # Both sides round the same sub-millisecond epoch, and JS and Python round a .5 tie apart.
    assert abs(real["epochMs"] - create_dt.timestamp() * 1000) <= 1, (
        f"JS v3 {version} read the instant as epochMs {real['epochMs']!r}; botocore's "
        f"create_table said {create_dt!r} ({round(create_dt.timestamp() * 1000)!r}) -- the two "
        "deserializers disagree on when the table was created")
    assert not real["iso"].startswith("1970"), (
        f"JS v3 {version} read the real response as {real['iso']!r} -- a 1970 instant means the "
        "epoch number was coerced from something that was not a number")

    # ---- 5. loopback controls: the SAME JS deserializer reads the numeric encodings of the
    #         same response, so the real-table read above is attributable to the encoding. How
    #         each SDK treats the string forms is SDK behaviour, so only numeric arms are asserted.
    assert js["epochFloat"]["ok"] is True and \
        abs(js["epochFloat"]["epochMs"] - create_dt.timestamp() * 1000) <= 1, (
        f"JS misread the loopback epoch encoding: {js['epochFloat']!r} -- the loopback arm is "
        "not a faithful control, so the failures below could not be attributed to the encoding")
    assert js["numericString"]["ok"] is True, (
        f"JS refused a numeric-string epoch: {js['numericString']!r}; both SDKs accept that "
        "form, so it is not a divergence")

    # ---- 6. effect-absent on teardown: the table is verifiably gone before the check ends,
    #         so nothing outlives the run and `on_cleanup` is only the failure-path net.
    _teardown_function(ctx, lam, logs, fn_name)
    ddb.delete_table(TableName=table)
    deadline = time.time() + _budget_s(ctx, 300.0)
    gone = None
    while time.time() < deadline:
        try:
            ddb.describe_table(TableName=table)
        except ClientError as exc:
            gone = (exc.response.get("Error", {}).get("Code"),
                    exc.response.get("Error", {}).get("Message"))
            break
        time.sleep(2.0)
    if gone is None and _budget_spent(ctx):
        raise TimeoutError(f"table {table!r} deleted: the run budget ended first; not graded")
    expected_gone = ("ResourceNotFoundException",
                     f"Requested resource not found: Table: {table} not found")
    assert gone == expected_gone, (
        f"the table was still describable after delete_table, or refused otherwise: got "
        f"{gone!r}, expected {expected_gone!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
