"""apigw-cors-preflight-served-from-mock-options-header-mappings."""
from __future__ import annotations

import json
import random
import string
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "apigw-cors-preflight-served-from-mock-options-header-mappings"
GROUP = "cors"
SERVICES = ["apigateway"]

ORIGIN = "https://app.sim2real.example"
ALLOW_METHODS = "GET,OPTIONS"
ALLOW_HEADERS = "Content-Type,X-Sim2real-Probe"
GET_BODY = '{"cors":"ok"}'


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A CORS preflight to a resource with a MOCK OPTIONS method answers 200 with exactly the
    Access-Control-* headers its integration-response mappings declare, the GET carries its mapped
    Allow-Origin, and a sibling resource with no OPTIONS method does not answer the preflight."""
    ag = ctx.client("apigateway")
    api_id = _create_api(ctx, ag)
    cors = _child(ctx, ag, api_id, "cors")
    nocors = _child(ctx, ag, api_id, "nocors")

    _cors_get(ag, api_id, cors)
    _cors_options(ag, api_id, cors)
    _mock_method(ag, api_id, nocors, "GET", GET_BODY)
    stage = _deploy(ctx, ag, api_id)

    url = _apigw_url(ctx, api_id, stage, "/cors")
    preflight = {
        "Origin": ORIGIN,
        "Access-Control-Request-Method": "GET",
        "Access-Control-Request-Headers": "x-sim2real-probe",
    }
    status, headers, text = _poll(
        lambda: _http("OPTIONS", url, headers=preflight),
        lambda s, h, t: s == 200,
        description=f"OPTIONS preflight {url} to be answered",
    )
    got = {k: headers.get(k) for k in (
        "access-control-allow-origin", "access-control-allow-methods",
        "access-control-allow-headers")}
    want = {
        "access-control-allow-origin": ORIGIN,
        "access-control-allow-methods": ALLOW_METHODS,
        "access-control-allow-headers": ALLOW_HEADERS,
    }
    assert got == want, f"preflight Access-Control-* headers {got!r} != declared {want!r}"
    assert text == "", f"the preflight body must be the empty MOCK template; got {text!r}"

    status, headers, text = _http("GET", url, headers={"Origin": ORIGIN})
    assert status == 200 and _json(text) == json.loads(GET_BODY), (
        f"the actual GET must be served the MOCK body; got ({status}, {text!r})"
    )
    assert headers.get("access-control-allow-origin") == ORIGIN, (
        f"the GET must carry its mapped Access-Control-Allow-Origin {ORIGIN!r}; got "
        f"{headers.get('access-control-allow-origin')!r}"
    )
    assert "access-control-allow-methods" not in headers, (
        f"Allow-Methods is mapped only on OPTIONS; the GET must not carry it: {headers!r}"
    )

    # Contrast: the sibling resource has no OPTIONS method, so nothing answers its preflight.
    nourl = _apigw_url(ctx, api_id, stage, "/nocors")
    status, headers, text = _http("OPTIONS", nourl, headers=preflight)
    assert status == 403, (
        f"a preflight to a resource with no OPTIONS method must be 403; got ({status}, {text!r})"
    )
    assert headers.get("x-amzn-errortype", "").split(":", 1)[0] == "MissingAuthenticationTokenException", (
        f"x-amzn-ErrorType must be MissingAuthenticationTokenException; got "
        f"{headers.get('x-amzn-errortype')!r}"
    )
    assert "access-control-allow-origin" not in headers, (
        f"no CORS header may be invented for a resource that declares none: {headers!r}"
    )
    status, _, text = _http("GET", nourl)
    assert status == 200 and _json(text) == json.loads(GET_BODY), (
        f"the sibling GET itself must still be served; got ({status}, {text!r})"
    )


def _cors_get(ag, api_id, resource_id):
    ag.put_method(restApiId=api_id, resourceId=resource_id, httpMethod="GET",
                  authorizationType="NONE")
    ag.put_integration(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    ag.put_method_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200",
        responseParameters={"method.response.header.Access-Control-Allow-Origin": False},
    )
    ag.put_integration_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200",
        selectionPattern="",
        responseParameters={"method.response.header.Access-Control-Allow-Origin": f"'{ORIGIN}'"},
        responseTemplates={"application/json": GET_BODY},
    )


def _cors_options(ag, api_id, resource_id):
    names = ("Access-Control-Allow-Origin", "Access-Control-Allow-Methods",
             "Access-Control-Allow-Headers")
    ag.put_method(restApiId=api_id, resourceId=resource_id, httpMethod="OPTIONS",
                  authorizationType="NONE")
    ag.put_integration(
        restApiId=api_id, resourceId=resource_id, httpMethod="OPTIONS", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    ag.put_method_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="OPTIONS", statusCode="200",
        responseParameters={f"method.response.header.{n}": False for n in names},
    )
    values = dict(zip(names, (ORIGIN, ALLOW_METHODS, ALLOW_HEADERS)))
    ag.put_integration_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="OPTIONS", statusCode="200",
        selectionPattern="",
        responseParameters={f"method.response.header.{n}": f"'{v}'" for n, v in values.items()},
        responseTemplates={"application/json": ""},
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
