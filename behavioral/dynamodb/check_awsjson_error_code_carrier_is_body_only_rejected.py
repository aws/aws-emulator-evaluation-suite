"""awsjson-error-code-carrier-is-body-only-rejected."""
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

CHECK = "awsjson-error-code-carrier-is-body-only-rejected"
GROUP = 'multi-sdk-error-vocabulary-rejected'
SERVICES = ['dynamodb']

#: Throwaway keys for the loopback servers below; the real credentials never reach them.
_LOOPBACK_CREDS = {"aws_access_key_id": "loopbackonly", "aws_secret_access_key": "loopbackonly"}

_RNF = 'ResourceNotFoundException'
_NAMESPACE = 'com.amazonaws.dynamodb.v20120810'
_JS_SOURCE = r'''
import http from "node:http";
import {DynamoDBClient, DescribeTableCommand, ResourceNotFoundException}
  from "@aws-sdk/client-dynamodb";
import pj from "@aws-sdk/client-dynamodb/package.json" with {type: "json"};

const describe = (cl) => cl.send(new DescribeTableCommand({TableName: "t"}));

const local = async (status, headers, body) => {
  const srv = http.createServer((req, rep) => {
    let d = ""; req.on("data", (c) => d += c);
    req.on("end", () => { rep.writeHead(status, headers); rep.end(body); });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const cl = new DynamoDBClient({
    region: "us-west-2", endpoint: `http://127.0.0.1:${srv.address().port}`,
    credentials: {accessKeyId: "loopbackonly", secretAccessKey: "loopback"},
    maxAttempts: 1});
  try { await describe(cl); return {ok: true}; }
  catch (e) {
    return {ok: false, ctor: e.constructor.name, name: e.name,
            message: String(e.message).slice(0, 200),
            isTyped: e instanceof ResourceNotFoundException,
            httpStatusCode: e.$metadata?.httpStatusCode ?? null};
  } finally { srv.close(); }
};

export const handler = async (ev) => {
  const out = {sdkVersion: pj.version, node: process.version};
  const cl = new DynamoDBClient({region: ev.region});
  const probe = async (key, name) => {
    try {
      const r = await cl.send(new DescribeTableCommand({TableName: name}));
      out[key] = {ok: true, tableName: r.Table.TableName, status: r.Table.TableStatus};
    } catch (e) {
      out[key] = {ok: false, ctor: e.constructor.name, name: e.name, message: e.message,
                  isTyped: e instanceof ResourceNotFoundException,
                  httpStatusCode: e.$metadata?.httpStatusCode ?? null,
                  requestId: e.$metadata?.requestId ?? null};
    }
  };
  await probe("absent", ev.absent);
  await probe("control", ev.table);
  const ct = {"content-type": "application/x-amz-json-1.0"};
  const typed = JSON.stringify(
      {__type: `${ev.namespace}#ResourceNotFoundException`, message: "loopback"});
  out.headerOnly = await local(
      400, {...ct, "x-amzn-errortype": "ResourceNotFoundException:http://internal"},
      JSON.stringify({message: "loopback"}));
  out.bodyOnly = await local(400, ct, typed);
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


def _error(fn):
    """Call fn(); return the botocore ClientError. Raises if the call unexpectedly SUCCEEDS --
    an emulator accepting input real AWS refuses must never be reported as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc
    raise AssertionError(f"real AWS refuses this call; the target returned {result!r}")


class _CannedHandler(http.server.BaseHTTPRequestHandler):
    """Serve one canned error response so botocore's own awsJson parser reads it."""

    status = 400
    extra_headers: dict = {}
    body = b'{}'

    def do_POST(self):  # noqa: N802 - BaseHTTPRequestHandler's contract
        self.rfile.read(int(self.headers.get("content-length") or 0))
        self.send_response(self.status)
        self.send_header("content-type", "application/x-amz-json-1.0")
        for key, value in self.extra_headers.items():
            self.send_header(key, value)
        self.send_header("content-length", str(len(self.body)))
        self.end_headers()
        self.wfile.write(self.body)

    def log_message(self, *args):
        return


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "concern:representation", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """DynamoDB sends an awsJson error code only in the namespaced body `__type`, never in
    x-amzn-errortype: botocore reads only the body, while the JS v3 SDK also reads the header.
    """
    import urllib3

    ddb = ctx.client("dynamodb")
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]

    base = ctx.unique_name("sim2real-behav-h1err-")
    table = base + "-t"
    absent = base + "-absent"

    ddb.create_table(
        TableName=table, BillingMode="PAY_PER_REQUEST",
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _absent_ok(lambda: ddb.delete_table(TableName=table)))
    _await_table_active(ctx, ddb, table)

    # ---- 1. botocore's read of the real refusal: a modeled class, not the '400' fallback.
    exc = _error(lambda: ddb.describe_table(TableName=absent))
    err = exc.response["Error"]
    assert err["Code"] == _RNF, (
        f"botocore reported Error.Code {err['Code']!r}, expected {_RNF!r}. '400' here would "
        "mean the body carried no __type, which is the only carrier botocore reads for awsJson")
    assert type(exc).__name__ == _RNF, (
        f"botocore raised {type(exc).__name__!r}, expected the modeled {_RNF!r}")
    assert exc.response["ResponseMetadata"]["HTTPStatusCode"] == 400, (
        f"status was {exc.response['ResponseMetadata']['HTTPStatusCode']!r}")

    # ---- 2. the bytes: __type only, #-namespaced and API-version-qualified, no header.
    raw_creds = ddb._request_signer._credentials
    frozen = (raw_creds.get_frozen_credentials()
              if hasattr(raw_creds, "get_frozen_credentials") else raw_creds)
    endpoint = ddb.meta.endpoint_url
    # The target's own TLS trust: on real AWS the system CAs, on an emulator its pinned chain.
    verify = ctx.http_verify
    pool = urllib3.PoolManager(cert_reqs="CERT_REQUIRED" if verify else "CERT_NONE",
                               ca_certs=verify if isinstance(verify, str) else None)

    def raw(body: dict, *, break_signature: bool = False):
        data = json.dumps(body).encode()
        req = AWSRequest(method="POST", url=endpoint, data=data, headers={
            "content-type": "application/x-amz-json-1.0",
            "x-amz-target": "DynamoDB_20120810.DescribeTable"})
        SigV4Auth(frozen, "dynamodb", ctx.region).add_auth(req)
        sent = dict(req.headers.items())
        if break_signature:
            sent["Authorization"] = sent["Authorization"][:-4] + "0000"
        resp = pool.request("POST", endpoint, body=data, headers=sent, retries=False)
        return (resp.status, {k.lower(): v for k, v in resp.headers.items()},
                json.loads(resp.data) if resp.data else {})

    status, headers, body = raw({"TableName": absent})
    assert status == 400, f"raw DescribeTable on an absent table gave {status!r}: {body!r}"
    assert body.get("__type") == f"{_NAMESPACE}#{_RNF}", (
        f"body __type was {body.get('__type')!r}, expected {_NAMESPACE + '#' + _RNF!r} -- the "
        "namespace is API-version-qualified, which a hand-written error writer omits")
    assert "x-amzn-errortype" not in headers, (
        f"DynamoDB sent x-amzn-errortype {headers.get('x-amzn-errortype')!r}; measured, real "
        "DynamoDB sends NO such header for awsJson1.0, so an emulator that adds one is "
        "diverging even though wire's expected-subset diff cannot see it")
    assert headers.get("x-amz-crc32"), (
        f"the error response carried no x-amz-crc32 header: {headers!r} -- DynamoDB checksums "
        "error bodies too, and botocore validates it")
    assert body.get("message") == err["Message"], (
        f"the raw body message {body.get('message')!r} != botocore's {err['Message']!r}")

    # ---- 3. a DIFFERENT refusal on the same route: an auth failure is not collapsed into the
    #         resource-missing one, and it uses a different namespace.
    status, _headers, body_sig = raw({"TableName": table}, break_signature=True)
    assert status == 400, f"a tampered signature gave {status!r}: {body_sig!r}"
    assert body_sig.get("__type") == "com.amazon.coral.service#InvalidSignatureException", (
        f"a tampered signature gave __type {body_sig.get('__type')!r}, expected "
        "'com.amazon.coral.service#InvalidSignatureException' -- note DynamoDB answers 400, not "
        "403, and uses the coral namespace here rather than its own")
    assert body_sig.get("__type") != body.get("__type"), (
        "an auth failure and a missing resource collapsed to one error code")

    # ---- 4. botocore's precedence, measured against loopback: with the code ONLY in
    #         x-amzn-errortype it falls back to the HTTP status and produces no modeled class.
    def serve(status_code: int, extra: dict, payload: dict):
        handler = type("_H", (_CannedHandler,), {
            "status": status_code, "extra_headers": extra,
            "body": json.dumps(payload).encode()})
        server = http.server.HTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            # Loopback only, throwaway credentials: nothing here reaches AWS, so the real
            # credentials are deliberately not used and cannot leak into this client.
            client = ctx.client(
                "dynamodb", endpoint_url=f"http://127.0.0.1:{server.server_address[1]}",
                creds=_LOOPBACK_CREDS, config=Config(retries={"max_attempts": 0}))
            return _error(lambda: client.describe_table(TableName="t"))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=10.0)

    header_only = serve(
        400, {"x-amzn-errortype": f"{_RNF}:http://internal"}, {"message": "loopback"})
    assert header_only.response["Error"]["Code"] == "400", (
        f"botocore read a header-only awsJson error as "
        f"{header_only.response['Error']['Code']!r}, expected the '400' status fallback -- "
        "BaseJSONParser._do_error_parse never consults x-amzn-errortype")
    assert type(header_only).__name__ == "ClientError", (
        f"botocore raised {type(header_only).__name__!r} for a header-only error, expected the "
        "generic 'ClientError': it had no code to match a modeled shape against")
    body_only = serve(400, {}, {"__type": f"{_NAMESPACE}#{_RNF}", "message": "loopback"})
    assert body_only.response["Error"]["Code"] == _RNF, (
        f"botocore read a body-only awsJson error as "
        f"{body_only.response['Error']['Code']!r}, expected {_RNF!r} -- the control that makes "
        "the header-only result attributable to the carrier")

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
    # IAM propagation exposes no condition to poll, so the bounded retry below -- not a sleep --
    # is what makes this correct.
    fn = None
    deadline = time.time() + _budget_s(ctx, 120.0)
    while fn is None:
        try:
            fn = lam.create_function(
                FunctionName=fn_name, Runtime="nodejs22.x", Role=role_arn,
                Handler="index.handler", Code={"ZipFile": buf.getvalue()},
                Timeout=60, MemorySize=512, Tags={"sim2real": CHECK})
        except ClientError as exc2:
            code = exc2.response.get("Error", {}).get("Code")
            if code == "InvalidParameterValueException" and time.time() >= deadline and _budget_spent(ctx):
                raise TimeoutError("the function's role propagating: the run budget ended first; not graded") from None
            assert code == "InvalidParameterValueException" and time.time() < deadline, (
                f"create_function failed with {code!r}: {exc2}")
            time.sleep(2.0)
    ctx.on_cleanup(lambda: _absent_ok(
        lambda: logs.delete_log_group(logGroupName=f"/aws/lambda/{fn_name}")))
    ctx.on_cleanup(lambda: _absent_ok(lambda: lam.delete_function(FunctionName=fn_name)))
    _await_function_active(ctx, lam, fn_name)

    event = json.dumps({"region": ctx.region, "table": table, "absent": absent,
                        "namespace": _NAMESPACE}).encode()
    js = None
    deadline = time.time() + _budget_s(ctx, 180.0)
    while True:
        invoked = lam.invoke(FunctionName=fn_name, Payload=event, LogType="Tail")
        assert invoked.get("FunctionError") is None, (
            f"the JS v3 consumer failed: {invoked['Payload'].read()!r}")
        js = json.loads(invoked["Payload"].read())
        if js.get("control", {}).get("ok") is True or time.time() > deadline:
            break
        time.sleep(2.0)  # bounded retry over IAM propagation at first use of the permission
    if js["control"].get("ok") is not True and _budget_spent(ctx):
        raise TimeoutError("the JS consumer's role taking effect: the run budget ended first; not graded")
    assert js["control"].get("ok") is True, (
        f"the JS consumer's role never became effective within 180s: {js!r}")
    version = js["sdkVersion"]
    assert version.startswith("3."), (
        f"the nodejs22.x runtime bundled @aws-sdk/client-dynamodb {version!r}, not a v3")

    # ---- 5. the second deserializer agrees with botocore on the REAL response.
    got = js["absent"]
    assert got["ok"] is False, f"the JS consumer described an absent table: {got!r}"
    assert got["ctor"] == _RNF, (
        f"JS v3 {version} constructed {got['ctor']!r}, expected {_RNF!r} -- the constructor, so "
        "a generic error carrying a hand-set `name` cannot pass")
    assert got["isTyped"] is True, (
        f"JS v3 {version} did not produce its MODELED {_RNF}: {got!r} -- a "
        "`catch (e) {{ if (e instanceof ResourceNotFoundException) createTable() }}` "
        "auto-provision branch would be dead code against this response")
    assert got["httpStatusCode"] == 400, f"JS saw status {got['httpStatusCode']!r}"
    assert isinstance(got["requestId"], str) and got["requestId"], (
        f"JS found no request id: {got!r}")
    assert got["message"] == err["Message"], (
        f"the two deserializers disagree on the message: JS {got['message']!r} vs botocore "
        f"{err['Message']!r}")

    # ---- 6. THE divergence: on the header-only response botocore reported '400' (assertion 4)
    #         while the same bytes give JS its modeled class. Two SDKs, one response, and the
    #         emulator's choice of carrier decides which one breaks.
    js_header_only = js["headerOnly"]
    assert js_header_only["ok"] is False, (
        f"JS accepted a 400 as a success: {js_header_only!r}")
    assert js_header_only["name"] == _RNF, (
        f"JS v3 {version} read a header-only awsJson error as {js_header_only['name']!r}, "
        f"expected {_RNF!r} -- it reads x-amzn-errortype FIRST, which botocore never reads")
    assert js_header_only["isTyped"] is True, (
        f"JS did not construct its modeled class from the header alone: {js_header_only!r}")
    assert js_header_only["name"] != header_only.response["Error"]["Code"], (
        f"both SDKs reported {js_header_only['name']!r} for the header-only response; measured, "
        f"botocore says {header_only.response['Error']['Code']!r} and JS says {_RNF!r}. If they "
        "have converged, the carrier no longer matters and this check must be re-measured")
    assert js["bodyOnly"]["name"] == _RNF and js["bodyOnly"]["isTyped"] is True, (
        f"JS misread a body-only error: {js['bodyOnly']!r} -- the control that makes the "
        "header-only divergence attributable to the carrier")

    # ---- 7. positive control on real AWS: the same route, same client, existing table.
    control = js["control"]
    assert control["tableName"] == table and control["status"] == "ACTIVE", (
        f"the JS consumer could not read the real table: {control!r}")
    assert ddb.describe_table(TableName=table)["Table"]["TableStatus"] == "ACTIVE", (
        "botocore could not read the real table either, so the refusals above are not "
        "attributable to the absent name")

    # ---- 8. effect-absent: the refusals created nothing, and the absent name is still absent.
    names = []
    token = None
    while True:
        page = ddb.list_tables(**({"ExclusiveStartTableName": token} if token else {}))
        names.extend(page.get("TableNames", []))
        token = page.get("LastEvaluatedTableName")
        if not token:
            break
    assert table in names, f"the control table is missing from list_tables: {names[:20]!r}"
    assert absent not in names, (
        f"a refused DescribeTable created {absent!r}: {[n for n in names if base in n]!r}")

    # ---- 9. verified teardown inline, so nothing outlives the run.
    _teardown_function(ctx, lam, logs, fn_name)
    ddb.delete_table(TableName=table)
    deadline = time.time() + _budget_s(ctx, 300.0)
    gone = None
    while time.time() < deadline:
        try:
            ddb.describe_table(TableName=table)
        except ClientError as exc3:
            gone = exc3.response.get("Error", {}).get("Code")
            break
        time.sleep(2.0)
    if gone is None and _budget_spent(ctx):
        raise TimeoutError(f"table {table!r} deleted: the run budget ended first; not graded")
    assert gone == _RNF, f"the table was still describable after delete_table (code {gone!r})"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
