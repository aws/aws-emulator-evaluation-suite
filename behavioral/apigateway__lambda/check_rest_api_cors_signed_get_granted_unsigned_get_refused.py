"""rest-api-cors-signed-get-granted-unsigned-get-refused."""
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

CHECK = "rest-api-cors-signed-get-granted-unsigned-get-refused"
GROUP = "cors"
SERVICES = ["apigateway", "lambda"]

ALLOWED = "https://app.example.com"
FOREIGN = "https://other.example.net"
#: A browser asks for the request headers a SigV4-signing page sets, lower-cased and sorted.
REQUEST_HEADERS = "authorization,x-amz-date"
#: The static grant the MOCK OPTIONS method answers every preflight with.
PREFLIGHT_GRANT = {
    "Access-Control-Allow-Origin": ALLOWED,
    "Access-Control-Allow-Methods": "GET,OPTIONS",
    "Access-Control-Allow-Headers": REQUEST_HEADERS,
}
MARKER = "sim2real-browser-cors"
HANDLER = f"""\
import json


def handler(event, context):
    headers = {{k.lower(): v for k, v in (event.get("headers") or {{}}).items()}}
    seen = {{"origin": headers.get("origin")}}
    out = {{"Content-Type": "application/json", "x-app-marker": "{MARKER}", "Vary": "Origin"}}
    if headers.get("origin") == "{ALLOWED}":
        out["Access-Control-Allow-Origin"] = "{ALLOWED}"
        out["Access-Control-Expose-Headers"] = "x-app-marker"
    return {{"statusCode": 200, "headers": out,
            "body": json.dumps({{"marker": "{MARKER}", "seen": seen}})}}
"""


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A browser's cross-site preflight gets the MOCK OPTIONS grant and its signed GET the proxy's
    Allow-Origin; an unsigned GET is refused with no CORS header, a foreign origin gets no grant.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/how-to-cors.html
    """
    ag = ctx.client("apigateway")
    partition = _partition(ctx)
    fn_name, fn_arn = _create_function(ctx)
    api_id = ag.create_rest_api(name=ctx.unique_name("sim2real-xsvc-cors-"),
                                endpointConfiguration={"types": ["REGIONAL"]},
                                tags={"sim2real": CHECK})["id"]
    ctx.on_cleanup(lambda: _delete_rest_api(ag, api_id))
    root = next(r["id"] for r in ag.get_resources(restApiId=api_id)["items"] if r["path"] == "/")
    res = ag.create_resource(restApiId=api_id, parentId=root, pathPart="items")["id"]
    _mock_options(ag, api_id, res)
    ag.put_method(restApiId=api_id, resourceId=res, httpMethod="GET", authorizationType="AWS_IAM")
    ag.put_integration(
        restApiId=api_id, resourceId=res, httpMethod="GET", type="AWS_PROXY",
        integrationHttpMethod="POST",
        uri=f"arn:{partition}:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/{fn_arn}/invocations",
    )
    ctx.client("lambda").add_permission(
        FunctionName=fn_name, StatementId="sim2real-apigw", Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=f"arn:{partition}:execute-api:{ctx.region}:{ctx.account}:{api_id}/*/GET/items",
    )
    ag.create_deployment(restApiId=api_id, stageName="live")
    url = f"{ctx.api_url(api_id, 'live')}/items"

    # Positive control: the cross-origin signed GET from the allowed origin reaches the handler.
    status, hdrs, body = _poll(ctx, lambda: _signed(ctx, "GET", url, ALLOWED), 200,
                               description=f"signed GET {url} from {ALLOWED}")
    served = json.loads(body)
    assert served == {"marker": MARKER, "seen": {"origin": ALLOWED}}, (
        f"the handler must see the browser's Origin, got {served!r}"
    )
    assert _cors(hdrs) == {"access-control-allow-origin": ALLOWED,
                           "access-control-expose-headers": "x-app-marker"}, (
        f"the allowed GET must carry exactly the proxy's CORS headers, got {_cors(hdrs)!r}"
    )

    # The browser's unsigned preflight for that GET is answered by the MOCK OPTIONS method.
    want = {k.lower(): v for k, v in PREFLIGHT_GRANT.items()}
    status, hdrs, body = _http(ctx, "OPTIONS", url, _preflight(ALLOWED))
    assert (status, body) == (200, ""), f"allowed preflight: want (200, ''), got {(status, body)!r}"
    assert _cors(hdrs) == want, f"the preflight must carry exactly the MOCK grant, got {_cors(hdrs)!r}"

    # Negative: a page that forgets to sign is refused before the handler, with no CORS header.
    status, hdrs, body = _http(ctx, "GET", url, {"Origin": ALLOWED})
    assert (status, json.loads(body)) == (403, {"message": "Missing Authentication Token"}), (
        f"an unsigned GET on an AWS_IAM method: want 403 Missing Authentication Token, got "
        f"{(status, body)!r}"
    )
    assert _cors(hdrs) == {}, f"the gateway's own 403 carries no CORS header, got {_cors(hdrs)!r}"

    # Negative: a foreign origin gets only the allowed origin's static grant, and no Allow-Origin
    # on its served GET.
    status, hdrs, body = _http(ctx, "OPTIONS", url, _preflight(FOREIGN))
    assert (status, _cors(hdrs)) == (200, want), (
        f"a foreign preflight gets the same static grant naming {ALLOWED!r}, got "
        f"{(status, _cors(hdrs))!r}"
    )
    status, hdrs, body = _signed(ctx, "GET", url, FOREIGN)
    assert status == 200 and json.loads(body)["seen"]["origin"] == FOREIGN, (
        f"CORS is not enforced server side: the foreign GET is still served, got {status!r} {body!r}"
    )
    assert _cors(hdrs) == {}, f"a foreign-origin GET must carry no CORS header, got {_cors(hdrs)!r}"


def _mock_options(ag, api_id: str, res: str) -> None:
    """An unauthenticated MOCK OPTIONS method answering PREFLIGHT_GRANT with an empty body."""
    params = {f"method.response.header.{k}": False for k in PREFLIGHT_GRANT}
    ag.put_method(restApiId=api_id, resourceId=res, httpMethod="OPTIONS", authorizationType="NONE")
    ag.put_integration(restApiId=api_id, resourceId=res, httpMethod="OPTIONS", type="MOCK",
                       requestTemplates={"application/json": '{"statusCode": 200}'})
    ag.put_method_response(restApiId=api_id, resourceId=res, httpMethod="OPTIONS",
                           statusCode="200", responseParameters=params)
    ag.put_integration_response(
        restApiId=api_id, resourceId=res, httpMethod="OPTIONS", statusCode="200",
        responseParameters={f"method.response.header.{k}": f"'{v}'"
                            for k, v in PREFLIGHT_GRANT.items()},
        responseTemplates={"application/json": ""},
    )


def _delete_rest_api(ag, api_id: str, *, budget_s: float = 150.0) -> None:
    """DeleteRestApi, retrying its account-wide TooManyRequestsException; not-found is done."""
    deadline = time.monotonic() + budget_s
    while True:
        try:
            ag.delete_rest_api(restApiId=api_id)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "NotFoundException":
                return
            if code != "TooManyRequestsException" or time.monotonic() >= deadline:
                raise
        time.sleep(10)


def _preflight(origin: str) -> dict:
    return {"Origin": origin, "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": REQUEST_HEADERS}


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


def _partition(ctx) -> str:
    """The caller's partition, read off its own ARN."""
    return ctx.client("sts").get_caller_identity()["Arn"].split(":")[1]


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
