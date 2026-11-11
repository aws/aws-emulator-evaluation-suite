"""invoke-http-api-httpproxy."""
from __future__ import annotations

import time
import urllib.error
import urllib.request


from behavioral_harness import tags

CHECK = "invoke-http-api-httpproxy"
GROUP = 'invoke'
SERVICES = ['apigatewayv2', 'apigateway']

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
TAGS_KV = [{"Key": k, "Value": v} for k, v in TAGS.items()]

# Data-plane failure marker: a detail containing it reads as a fidelity failure.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

def _http(method, url, body=None, headers=None):
    """HTTP request via urllib. Returns (status, headers_dict, body_str)."""
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, dict(resp.headers), resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode()

def _get_until_200(url, budget_s=90):
    """GET ``url`` until 200 or the budget runs out; return (status, body, last transport error).
    A new invoke host may not resolve or serve yet, so a transport error is retried, not final."""
    status, body = None, ""
    last_exc: Exception | None = None
    deadline = time.monotonic() + budget_s
    while time.monotonic() < deadline:
        try:
            status, _, body = _http("GET", url)
        except Exception as exc:  # noqa: BLE001 — DNS/connect warm-up, retry within the budget
            last_exc = exc
            time.sleep(3)
            continue
        if status == 200:
            break
        time.sleep(3)
    return status, body, last_exc


def _transport(last_exc):
    return f" (last transport error: {type(last_exc).__name__}: {last_exc})" if last_exc else ""

def _create_http_api(ctx):
    agw = ctx.client("apigatewayv2")
    api = agw.create_api(
        Name=ctx.unique_name("sim2real-behav-httpapi-"), ProtocolType="HTTP", Tags=TAGS
    )
    ctx.on_cleanup(lambda: agw.delete_api(ApiId=api["ApiId"]))
    return api["ApiId"], api["ApiEndpoint"]

def _invoke_url(ctx, api_endpoint, path, stage=None):
    p = path.lstrip("/")
    stg = stage or "$default"
    return f"{ctx.stage_url(api_endpoint, stg)}/{p}"

@tags("axis:happy-path", "cap:c1", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """HTTP_PROXY integration forwards the upstream response: the invoke URL returns the token
    served by a REST API MOCK upstream the check owns, so a stub answering 200 cannot pass."""
    agw = ctx.client("apigatewayv2")
    token = ctx.unique_name("sim2real-behav-upstream-")
    upstream = _mock_backend(ctx, token)
    # Positive control: a failure here is the upstream, not the proxy leg.
    pre_status, pre_body, pre_exc = _get_until_200(upstream)
    assert pre_status == 200 and pre_body == token, (
        f"{DATAPLANE_MARKER}: the upstream MOCK stage {upstream} did not serve its token, got "
        f"{pre_status}: {pre_body!r}" + _transport(pre_exc)
    )

    api_id, api_endpoint = _create_http_api(ctx)
    integ = agw.create_integration(
        ApiId=api_id,
        IntegrationType="HTTP_PROXY",
        IntegrationUri=upstream,
        IntegrationMethod="GET",
        PayloadFormatVersion="1.0",
    )
    agw.create_route(
        ApiId=api_id, RouteKey="GET /ip", Target=f"integrations/{integ['IntegrationId']}"
    )
    agw.create_stage(ApiId=api_id, StageName="$default", AutoDeploy=True)
    ctx.on_cleanup(lambda: agw.delete_stage(ApiId=api_id, StageName="$default"))

    url = _invoke_url(ctx, api_endpoint, "/ip", stage="$default")
    status, body, last_exc = _get_until_200(url)

    # Marked: the invoke URL is one the target built from the API it just created, so 90s of
    # refusing to serve it is a data-plane fidelity failure, not an environment problem.
    assert status == 200, (
        f"{DATAPLANE_MARKER}: expected 200 from HTTP_PROXY invoke URL {url}, got {status}: {body}"
        + _transport(last_exc)
    )
    # HTTP_PROXY is a transparent passthrough, so the invoked body is the upstream's token.
    assert body == token, (
        f"{DATAPLANE_MARKER}: expected HTTP_PROXY to forward the upstream body {token!r}, "
        f"got {body!r} from {url}"
    )


def _mock_backend(ctx, body: str) -> str:
    """The invoke URL of a REST API stage the check owns whose MOCK integration answers GET / with
    200 and ``body``: a backend on the target itself, so the proxy leg never leaves it."""
    ag = ctx.client("apigateway")
    rest_id = ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-backend-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags=TAGS,
    )["id"]
    ctx.on_cleanup(lambda: _delete_rest_api(ag, rest_id))
    root = next(r["id"] for r in ag.get_resources(restApiId=rest_id)["items"] if r["path"] == "/")
    ag.put_method(restApiId=rest_id, resourceId=root, httpMethod="GET", authorizationType="NONE")
    ag.put_integration(
        restApiId=rest_id, resourceId=root, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    ag.put_method_response(restApiId=rest_id, resourceId=root, httpMethod="GET", statusCode="200")
    ag.put_integration_response(
        restApiId=rest_id, resourceId=root, httpMethod="GET", statusCode="200",
        selectionPattern="", responseTemplates={"application/json": body},
    )
    ag.create_deployment(restApiId=rest_id, stageName="backend")
    return ctx.rest_api_url(rest_id, "backend")


def _delete_rest_api(ag, api_id, *, budget_s=150.0):
    """DeleteRestApi is throttled hard per account, so retry within a bounded budget and report on
    stderr if the API survives, since teardown exceptions are swallowed."""
    import sys

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + budget_s
    delay = 5.0
    while True:
        try:
            ag.delete_rest_api(restApiId=api_id)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "NotFoundException":
                return
            if code != "TooManyRequestsException" or time.monotonic() >= deadline:
                raise RuntimeError(f"rest api {api_id} not deleted: {code}") from exc
        time.sleep(delay)
        delay = min(delay * 2, 30.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
