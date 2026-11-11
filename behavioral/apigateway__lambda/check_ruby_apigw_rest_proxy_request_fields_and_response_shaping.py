"""ruby-apigw-rest-proxy-request-fields-and-response-shaping."""
from __future__ import annotations

import http.client
import io
import json
import ssl
import textwrap
import time
import urllib.parse
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ruby-apigw-rest-proxy-request-fields-and-response-shaping"
GROUP = "data-format"
SERVICES = ["apigateway", "lambda"]

# Echoes the request fields AWS_PROXY handed it, and shapes its own HTTP response from the path:
# /binary asks for a base64 body the way AWS requires for binary content; the body/headers below
# are literal constants the assertions can match on.
_HANDLER = """\
require 'json'
require 'base64'

def lambda_handler(event:, context:)
  if event['path'] == '/binary'
    return {
      'statusCode' => 201,
      'headers' => { 'Content-Type' => 'application/octet-stream', 'X-Ruby-Runtime' => 'ruby3.4' },
      'body' => Base64.strict_encode64("\\x00\\x01binary-ruby\\xff"),
      'isBase64Encoded' => true
    }
  end
  {
    'statusCode' => 200,
    'headers' => { 'Content-Type' => 'application/json', 'X-Ruby-Runtime' => 'ruby3.4' },
    'body' => JSON.generate({
      'httpMethod' => event['httpMethod'],
      'path' => event['path'],
      'queryStringParameters' => event['queryStringParameters'],
      'headerEcho' => (event['headers'] || {})['X-Sim2Real-Probe'],
      'body' => event['body'],
      'isBase64Encoded' => event['isBase64Encoded']
    }),
    'isBase64Encoded' => false
  }
end
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation",
      "concern:e2e", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A REST API's AWS_PROXY integration hands a ruby3.4 handler the method, path, query string
    and headers it received, and the handler's statusCode/headers/body/isBase64Encoded shape the
    exact HTTP response API Gateway returns, binary bodies included.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-proxy-integrations.html
    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-payload-encodings.html
    """
    fn = _function(ctx, _HANDLER)
    api_id, root_id = _rest_api(ctx)
    ag = ctx.client("apigateway")
    proxy_id = ag.create_resource(restApiId=api_id, parentId=root_id, pathPart="{proxy+}")["id"]
    uri = (f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/"
           f"{fn['arn']}/invocations")
    ag.put_method(restApiId=api_id, resourceId=proxy_id, httpMethod="ANY", authorizationType="NONE")
    ag.put_integration(restApiId=api_id, resourceId=proxy_id, httpMethod="ANY",
                       type="AWS_PROXY", integrationHttpMethod="POST", uri=uri)
    ctx.client("lambda").add_permission(
        FunctionName=fn["name"], StatementId="apigw-invoke", Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=f"arn:aws:execute-api:{ctx.region}:{ctx.account}:{api_id}/*/*")
    stage = "live"
    dep_id = ag.create_deployment(restApiId=api_id)["id"]
    ag.create_stage(restApiId=api_id, stageName=stage, deploymentId=dep_id)
    ctx.on_cleanup(_teardown(lambda: ag.delete_stage(restApiId=api_id, stageName=stage), "NotFoundException"))

    base = ctx.api_url(api_id, stage)
    probe_token = ctx.unique_name("probe")

    def _text_probe():
        return _raw_request("POST", base + "/widgets?a=1&a=2", [("X-Sim2Real-Probe", probe_token),
                                                                 ("Content-Type", "text/plain")],
                            body=b"hello-ruby", verify=ctx.http_verify)

    status, headers, text = _poll(ctx, _text_probe, lambda r: r[0] == 200, timeout_s=90, interval_s=2,
                                   what="the deployed stage starts answering 200")
    assert status == 200, f"expected 200 from the handler's statusCode, got {status}: {text[:300]!r}"
    assert headers.get("content-type") == "application/json", (
        f"expected the handler's Content-Type header to reach the caller, got {headers.get('content-type')!r}")
    assert headers.get("x-ruby-runtime") == "ruby3.4", (
        f"expected the handler's custom header to reach the caller, got {headers.get('x-ruby-runtime')!r}")
    ev = json.loads(text)
    assert ev["httpMethod"] == "POST", f"httpMethod reaching the handler was {ev['httpMethod']!r}"
    assert ev["path"] == "/widgets", f"path reaching the handler was {ev['path']!r}"
    assert ev["queryStringParameters"] == {"a": "2"}, (
        f"a repeated query parameter must arrive with only its last value, got {ev['queryStringParameters']!r}")
    assert ev["headerEcho"] == probe_token, (
        f"the custom request header must reach the handler verbatim, got {ev['headerEcho']!r}")
    assert ev["body"] == "hello-ruby", f"the request body must reach the handler verbatim, got {ev['body']!r}"
    assert ev["isBase64Encoded"] is False, (
        f"a text/plain body (not a binary media type) must not be base64'd, got {ev['isBase64Encoded']!r}")

    bstatus, bheaders, btext = _raw_request(
        "GET", base + "/binary", [("Accept", "application/octet-stream")], verify=ctx.http_verify)
    assert bstatus == 201, f"expected the handler's statusCode 201 for /binary, got {bstatus}"
    assert bheaders.get("content-type") == "application/octet-stream", (
        f"expected the handler's binary Content-Type, got {bheaders.get('content-type')!r}")
    assert btext.encode("latin-1") == b"\x00\x01binary-ruby\xff", (
        f"expected the handler's base64 body decoded back to the exact raw bytes, got {btext!r}")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise
    return run_undo


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll(ctx, probe, done, *, timeout_s, interval_s, what):
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        try:
            last = probe()
        except OSError as exc:
            last = (0, {}, repr(exc))
        if done(last):
            return last
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"{what}: the run budget ended first; not graded")
            raise AssertionError(f"timed out after {timeout_s}s waiting until {what}; last={last!r}")
        time.sleep(interval_s)


def _ssl_context(verify):
    if verify is False:
        return ssl._create_unverified_context()
    if isinstance(verify, str):
        return ssl.create_default_context(cafile=verify)
    return ssl.create_default_context()


def _raw_request(method, url, header_pairs, body=None, verify=True):
    """HTTP via http.client. Returns (status, lower-cased headers, body text, latin-1 safe)."""
    u = urllib.parse.urlsplit(url)
    if u.scheme == "http":
        conn = http.client.HTTPConnection(u.netloc, timeout=25)
    else:
        conn = http.client.HTTPSConnection(u.netloc, timeout=25, context=_ssl_context(verify))
    try:
        conn.putrequest(method, u.path + (f"?{u.query}" if u.query else ""), skip_accept_encoding=True)
        for k, v in header_pairs:
            conn.putheader(k, v)
        if body is not None:
            conn.putheader("Content-Length", str(len(body)))
        conn.endheaders()
        if body is not None:
            conn.send(body)
        resp = conn.getresponse()
        raw = resp.read()
        return (resp.status, {k.lower(): v for k, v in resp.getheaders()}, raw.decode("latin-1"))
    finally:
        conn.close()


def _zip(code: str, filename: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


def _execution_role(ctx) -> dict:
    """A Lambda execution role trusting only Lambda, with no permissions at all (none needed) and
    no logs permission, so the function never creates a log group."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-xsvc-role-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole"}]}
    role = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                           Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    return {"name": name, "arn": role["Arn"]}


def _function(ctx, code) -> dict:
    role = _execution_role(ctx)
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-xsvc-fn-")
    kwargs = {"FunctionName": name, "Runtime": "ruby3.4", "Handler": "lambda_function.lambda_handler",
              "Role": role["arn"], "Code": {"ZipFile": _zip(code, "lambda_function.rb")},
              "Timeout": 10, "MemorySize": 128, "Tags": {"sim2real": CHECK}}

    def create():
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "InvalidParameterValueException" and "cannot be assumed" in err.get("Message", ""):
                return None
            raise

    out = _poll(ctx, create, lambda r: r is not None, timeout_s=90, interval_s=2,
                what="CreateFunction accepts the fresh execution role")
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name), "ResourceNotFoundException"))
    conf = _poll(ctx, lambda: lam.get_function_configuration(FunctionName=name),
                 lambda c: c.get("State", "Active") in ("Active", "Failed"), timeout_s=90, interval_s=2,
                 what=f"function {name} leaves Pending")
    assert conf.get("State", "Active") == "Active", (
        f"function {name} ended {conf.get('State')!r}: {conf.get('StateReason')!r}")
    assert conf["Runtime"] == "ruby3.4", f"expected Runtime=ruby3.4, got {conf.get('Runtime')!r}"
    return {"name": name, "arn": out["FunctionArn"]}


def _rest_api(ctx):
    ag = ctx.client("apigateway")
    name = ctx.unique_name("sim2real-xsvc-api-")
    api_id = ag.create_rest_api(name=name, endpointConfiguration={"types": ["REGIONAL"]},
                                binaryMediaTypes=["application/octet-stream"],
                                tags={"sim2real": CHECK})["id"]
    ctx.on_cleanup(_teardown(lambda: ag.delete_rest_api(restApiId=api_id), "NotFoundException"))
    root_id = next(r["id"] for r in ag.get_resources(restApiId=api_id)["items"] if r["path"] == "/")
    return api_id, root_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
