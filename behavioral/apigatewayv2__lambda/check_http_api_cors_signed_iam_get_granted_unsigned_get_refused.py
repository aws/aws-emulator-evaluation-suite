"""http-api-cors-signed-iam-get-granted-unsigned-get-refused."""
from __future__ import annotations

import io
import json
import time
import zipfile

import requests

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "http-api-cors-signed-iam-get-granted-unsigned-get-refused"
GROUP = "cors"
SERVICES = ["apigatewayv2", "lambda"]

ALLOWED = "https://app.example.com"
FOREIGN = "https://other.example.net"
CORS = {
    "AllowOrigins": [ALLOWED],
    "AllowMethods": ["GET"],
    "AllowHeaders": ["authorization", "x-amz-date"],
    "ExposeHeaders": ["x-app-marker"],
}
MARKER = "sim2real-browser-cors"
HANDLER = f"""\
import json


def handler(event, context):
    headers = event.get("headers") or {{}}
    seen = {{"origin": headers.get("origin")}}
    return {{
        "statusCode": 200,
        "headers": {{"Content-Type": "application/json", "x-app-marker": "{MARKER}"}},
        "body": json.dumps({{"marker": "{MARKER}", "seen": seen}}),
    }}
"""


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A SigV4-signed GET carrying Origin on an AWS_IAM HTTP API route reaches the handler with the
    CorsConfiguration grant (none for a foreign origin); the same GET unsigned is refused 403.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-cors.html
    """
    agw = ctx.client("apigatewayv2")
    fn_name, fn_arn = _create_function(ctx)
    api = agw.create_api(Name=ctx.unique_name("sim2real-xsvc-cors-"), ProtocolType="HTTP",
                         CorsConfiguration=dict(CORS), Tags={"sim2real": CHECK})
    api_id = api["ApiId"]
    ctx.on_cleanup(_teardown(lambda: agw.delete_api(ApiId=api_id), "NotFoundException"))
    integ = agw.create_integration(ApiId=api_id, IntegrationType="AWS_PROXY",
                                   IntegrationUri=fn_arn, PayloadFormatVersion="2.0")
    agw.create_route(ApiId=api_id, RouteKey="GET /items", AuthorizationType="AWS_IAM",
                     Target=f"integrations/{integ['IntegrationId']}")
    agw.create_stage(ApiId=api_id, StageName="$default", AutoDeploy=True)
    ctx.client("lambda").add_permission(
        FunctionName=fn_name, StatementId="sim2real-apigw", Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=f"arn:{_partition(ctx)}:execute-api:{ctx.region}:{ctx.account}:{api_id}/*/*",
    )
    url = f"{ctx.stage_url(api['ApiEndpoint'], '$default')}/items"

    # Positive control: the signed GET from the allowed origin reaches the handler with the grant.
    status, hdrs, body = _poll(ctx, lambda: _signed(ctx, "GET", url, ALLOWED), 200,
                               description=f"signed GET {url} from {ALLOWED}")
    served = json.loads(body)
    assert served == {"marker": MARKER, "seen": {"origin": ALLOWED}}, (
        f"the handler must see the caller's Origin, got {served!r}"
    )
    assert _cors(hdrs) == {"access-control-allow-origin": ALLOWED,
                           "access-control-expose-headers": "x-app-marker"}, (
        f"the allowed GET must carry exactly Allow-Origin and Expose-Headers, got {_cors(hdrs)!r}"
    )

    # The same signed GET from a foreign origin is served, with no grant.
    status, hdrs, body = _signed(ctx, "GET", url, FOREIGN)
    assert status == 200 and json.loads(body)["seen"]["origin"] == FOREIGN, (
        f"CORS is not enforced server side: the foreign GET is still served, got {status!r} {body!r}"
    )
    assert _cors(hdrs) == {}, f"a foreign-origin GET must carry no CORS header, got {_cors(hdrs)!r}"

    # Negative: the allowed origin's GET without a signature is refused by the IAM route.
    status, hdrs, body = _http(ctx, "GET", url, {"Origin": ALLOWED})
    assert (status, body) == (403, '{"message":"Forbidden"}'), (
        f"an unsigned GET on an AWS_IAM route: want 403 Forbidden, got {(status, body)!r}"
    )
    assert "x-app-marker" not in hdrs, f"the refused GET reached the handler: {hdrs!r}"
    assert _cors(hdrs) == {"access-control-allow-origin": ALLOWED,
                           "access-control-expose-headers": "x-app-marker"}, (
        f"the refusal must carry the CorsConfiguration grant, got {_cors(hdrs)!r}"
    )


def _partition(ctx) -> str:
    """The caller's partition, read off its own ARN."""
    return ctx.client("sts").get_caller_identity()["Arn"].split(":")[1]


def _signed(ctx, method: str, url: str, origin: str):
    """A page's SigV4-signed fetch(): the page signs, then the browser adds Origin."""
    env = ctx.subprocess_env()
    creds = Credentials(env["AWS_ACCESS_KEY_ID"], env["AWS_SECRET_ACCESS_KEY"],
                        env.get("AWS_SESSION_TOKEN"))
    req = AWSRequest(method=method, url=url)
    SigV4Auth(creds, "execute-api", ctx.region).add_auth(req)
    return _http(ctx, method, url, {**dict(req.headers.items()), "Origin": origin})


def _http(ctx, method: str, url: str, headers: dict):
    """(status, {lower-cased header: value}, body text); never raises on an HTTP error status."""
    resp = requests.request(method, url, headers=headers, timeout=20, verify=ctx.http_verify,
                            allow_redirects=False)
    return resp.status_code, {k.lower(): v for k, v in resp.headers.items()}, resp.text


def _poll(ctx, probe, want: int, *, description: str, timeout_s: float = 120.0):
    """Re-issue probe() until it answers `want`, within the check's time left: a new endpoint and
    its grants become servable asynchronously."""
    left = ctx.time_left()
    timeout_s = timeout_s if left is None else max(1.0, min(timeout_s, left - 15.0))
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = probe()
        except requests.RequestException as exc:
            last = (None, {}, repr(exc))
        if last[0] == want:
            return last
        time.sleep(3)
    raise AssertionError(f"{description} not answered {want} within {timeout_s}s; last {last!r}")


def _cors(hdrs: dict) -> dict:
    return {k: v for k, v in hdrs.items() if k.startswith("access-control-")}


def _teardown(undo, *not_found: str):
    """A cleanup running undo() where a failed delete raises; only not_found codes mean gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _create_function(ctx) -> tuple[str, str]:
    """The handler with its own execution role; waits for Active. Returns (name, arn)."""
    iam, lam = ctx.client("iam"), ctx.client("lambda")
    role = ctx.unique_name("sim2real-xsvc-cors-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole"}]}
    role_arn = iam.create_role(RoleName=role, AssumeRolePolicyDocument=json.dumps(trust),
                               Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role), "NoSuchEntity"))
    name = ctx.unique_name("sim2real-xsvc-cors-")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", HANDLER)
    deadline = time.monotonic() + 90
    while True:
        try:
            arn = lam.create_function(
                FunctionName=name, Runtime="python3.12", Role=role_arn, Handler="index.handler",
                Code={"ZipFile": buf.getvalue()}, MemorySize=128, Timeout=10,
                Tags={"sim2real": CHECK})["FunctionArn"]
            break
        except ClientError as exc:
            # IAM propagation: a new role is not assumable by Lambda at once.
            if "cannot be assumed by Lambda" not in exc.response["Error"].get("Message", "") \
                    or time.monotonic() > deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name),
                             "ResourceNotFoundException"))
    deadline = time.monotonic() + 120
    while lam.get_function_configuration(FunctionName=name).get("State") != "Active":
        if time.monotonic() > deadline:
            raise AssertionError(f"function {name} not Active within 120s")
        time.sleep(2)
    return name, arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
