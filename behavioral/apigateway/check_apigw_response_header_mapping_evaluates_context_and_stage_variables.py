"""apigw-response-header-mapping-evaluates-context-and-stage-variables."""
from __future__ import annotations

import json
import random
import string
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "apigw-response-header-mapping-evaluates-context-and-stage-variables"
GROUP = "parameter-mapping"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """Integration-response header mappings are evaluated per request: a header mapped from
    context.requestId equals that request's id and differs across two requests, a stageVariables.<name>
    header carries the stage's value, and a static '...' literal is served verbatim."""
    ag = ctx.client("apigateway")
    api_id = _create_api(ctx, ag)
    resource_id = _child(ctx, ag, api_id, "mapped")
    ag.put_method(restApiId=api_id, resourceId=resource_id, httpMethod="GET",
                  authorizationType="NONE")
    ag.put_integration(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    names = ("X-Req-Id", "X-Stage-Flavor", "X-Static")
    ag.put_method_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200",
        responseParameters={f"method.response.header.{n}": False for n in names},
    )
    ag.put_integration_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200",
        selectionPattern="",
        responseParameters={
            "method.response.header.X-Req-Id": "context.requestId",
            "method.response.header.X-Stage-Flavor": "stageVariables.flavor",
            "method.response.header.X-Static": "'literal-value'",
        },
        responseTemplates={"application/json": '{"mapped":true}'},
    )
    stage = f"s{_unique_token()}"
    ag.create_deployment(restApiId=api_id, stageName=stage, variables={"flavor": "pistachio"})
    ctx.on_cleanup(lambda: ag.delete_stage(restApiId=api_id, stageName=stage))
    url = _apigw_url(ctx, api_id, stage, "/mapped")

    status, h1, text = _poll(
        lambda: _http("GET", url), lambda s, h, t: s == 200,
        description=f"GET {url} to be served",
    )
    assert _json(text) == {"mapped": True}, f"served {text!r}"
    assert h1.get("x-amzn-requestid"), f"precondition: no x-amzn-RequestId on the response {h1!r}"
    assert h1.get("x-req-id") == h1.get("x-amzn-requestid"), (
        f"context.requestId must evaluate to THIS request's id {h1.get('x-amzn-requestid')!r}; "
        f"header was {h1.get('x-req-id')!r}"
    )
    assert h1.get("x-stage-flavor") == "pistachio", (
        f"stageVariables.flavor must evaluate to the stage's value 'pistachio'; got "
        f"{h1.get('x-stage-flavor')!r}"
    )
    assert h1.get("x-static") == "literal-value", (
        f"a static mapping must be served verbatim without quotes; got {h1.get('x-static')!r}"
    )

    status, h2, _ = _http("GET", url)
    assert status == 200, f"second GET must be served; got {status!r}"
    assert h2.get("x-req-id") == h2.get("x-amzn-requestid") and h2.get("x-req-id") != h1.get("x-req-id"), (
        f"context.requestId must be re-evaluated per request: first {h1.get('x-req-id')!r}, "
        f"second {h2.get('x-req-id')!r} (x-amzn-RequestId {h2.get('x-amzn-requestid')!r})"
    )


def _unique_token(length=10):
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


def _root_id(ag, api_id):
    for item in ag.get_resources(restApiId=api_id, limit=500)["items"]:
        if item.get("path") == "/":
            return item["id"]
    raise AssertionError(f"root resource not found on {api_id!r}")


def _create_api(ctx, ag):
    api_id = ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: _delete_rest_api(ag, api_id))
    return api_id


def _delete_rest_api(ag, api_id, *, budget_s=150.0):
    """DeleteRestApi, retrying TooManyRequestsException (one call per 30 s per account) to budget_s;
    NotFoundException is done, anything else raises."""
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


def _child(ctx, ag, api_id, path_part):
    resource_id = ag.create_resource(
        restApiId=api_id, parentId=_root_id(ag, api_id), pathPart=path_part
    )["id"]
    ctx.on_cleanup(lambda: ag.delete_resource(restApiId=api_id, resourceId=resource_id))
    return resource_id


def _mock_method(ag, api_id, resource_id, http_method, response_template, authorization="NONE"):
    ag.put_method(
        restApiId=api_id, resourceId=resource_id, httpMethod=http_method,
        authorizationType=authorization,
    )
    ag.put_integration(
        restApiId=api_id, resourceId=resource_id, httpMethod=http_method, type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    ag.put_method_response(
        restApiId=api_id, resourceId=resource_id, httpMethod=http_method, statusCode="200",
    )
    ag.put_integration_response(
        restApiId=api_id, resourceId=resource_id, httpMethod=http_method, statusCode="200",
        selectionPattern="", responseTemplates={"application/json": response_template},
    )


def _deploy(ctx, ag, api_id):
    stage = f"s{_unique_token()}"
    ag.create_deployment(restApiId=api_id, stageName=stage)
    ctx.on_cleanup(lambda: ag.delete_stage(restApiId=api_id, stageName=stage))
    return stage


def _apigw_url(ctx, api_id, stage, path=""):
    return f"{ctx.rest_api_url(api_id, stage)}/{path.lstrip('/')}"


def _http(method, url, headers=None, body=None):
    """(status, lowercased headers, text); a transport error returns (None, {}, repr)."""
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310 - fixed https scheme
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, {k.lower(): v for k, v in (exc.headers or {}).items()}, exc.read().decode()
    except (urllib.error.URLError, OSError) as exc:
        return None, {}, repr(exc)


def _caller_credentials(ctx):
    """The harness's per-run credentials, via the one sanctioned seam (never the ambient chain)."""
    env = ctx.subprocess_env()
    akid, secret = env.get("AWS_ACCESS_KEY_ID"), env.get("AWS_SECRET_ACCESS_KEY")
    assert akid and secret, "ctx.subprocess_env() carried no credentials to sign with"
    return akid, secret, env.get("AWS_SESSION_TOKEN")


def _signed_get(ctx, url, akid, secret, token=None):
    """GET url SigV4-signed for service execute-api in ctx.region with the given key pair."""
    from botocore.auth import SigV4Auth
    from botocore.awsrequest import AWSRequest
    from botocore.credentials import Credentials

    req = AWSRequest(method="GET", url=url, headers={"Accept": "application/json"})
    SigV4Auth(Credentials(akid, secret, token), "execute-api", ctx.region).add_auth(req)
    return _http("GET", url, headers=dict(req.headers.items()))


def _poll(fn, predicate, *, timeout_s=180.0, interval_s=3.0, description="stage response"):
    """Re-issue fn() until predicate(status, headers, text) holds: a fresh deployment becomes
    servable asynchronously."""
    deadline = time.monotonic() + timeout_s
    while True:
        status, headers, text = fn()
        if predicate(status, headers, text):
            return status, headers, text
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} not observed within {timeout_s}s; last=({status!r}, {text[:400]!r})"
            )
        time.sleep(interval_s)


def _json(text):
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
