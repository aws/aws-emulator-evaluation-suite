"""deep-apigw-integration-request-validator-modes-validate-only-what-they-declare."""
from __future__ import annotations

import http.client
import json
import time
import urllib.parse

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-apigw-integration-request-validator-modes-validate-only-what-they-declare"
GROUP = "validation"
SERVICES = ["apigateway"]

_BAD_BODY = "Invalid request body"
_BAD_PARAMS = "Missing required request parameters: [tenant]"


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """Body-only, params-only, both and no request validator each enforce only what they declare.
    All four declare the same model and required `tenant` parameter; with none they are inert.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-method-request-validation.html
    """
    ag = ctx.client("apigateway")
    api_id, root_id = _create_rest_api(ctx, "validator-modes")
    model = "Order" + ctx.unique_name("m").replace("-", "").replace("_", "")[-10:]
    _c(ag.create_model, restApiId=api_id, name=model, contentType="application/json",
       schema=json.dumps({
           "$schema": "http://json-schema.org/draft-04/schema#", "title": model,
           "type": "object",
           "properties": {"sku": {"type": "string"},
                          "qty": {"type": "integer", "minimum": 1}},
           "required": ["sku", "qty"]}))

    modes = {"body": (True, False), "params": (False, True), "both": (True, True), "none": None}
    for route, flags in modes.items():
        validator_id = None
        if flags is not None:
            validator_id = _c(ag.create_request_validator, restApiId=api_id,
                              name=_xname(ctx, f"rv-{route}"),
                              validateRequestBody=flags[0],
                              validateRequestParameters=flags[1])["id"]
        rid = _c(ag.create_resource, restApiId=api_id, parentId=root_id, pathPart=route)["id"]
        kw = {"requestValidatorId": validator_id} if validator_id else {}
        _c(ag.put_method, restApiId=api_id, resourceId=rid, httpMethod="POST",
           authorizationType="NONE", requestModels={"application/json": model},
           requestParameters={"method.request.querystring.tenant": True}, **kw)
        _c(ag.put_integration, restApiId=api_id, resourceId=rid, httpMethod="POST",
           type="MOCK", requestTemplates={"application/json": '{"statusCode": 200}'})
        _c(ag.put_method_response, restApiId=api_id, resourceId=rid, httpMethod="POST",
           statusCode="200")
        _c(ag.put_integration_response, restApiId=api_id, resourceId=rid, httpMethod="POST",
           statusCode="200", selectionPattern="",
           responseTemplates={"application/json":
                              '{"ran": "' + route + '", '
                              '"tenant": "$input.params(\'tenant\')"}'})
    _deploy_stage(ctx, api_id, "v")

    tenant = ctx.unique_name("t")
    good = json.dumps({"sku": "a-1", "qty": 2}).encode()
    bad_min = json.dumps({"sku": "a-1", "qty": 0}).encode()
    bad_missing = json.dumps({"qty": 3}).encode()

    def post(route, body, with_tenant=True):
        url = _rest_invoke_url(ctx, api_id, "v", f"/{route}")
        if with_tenant:
            url += "?" + urllib.parse.urlencode({"tenant": tenant})
        return _raw_request("POST", url, [("Content-Type", "application/json")], body=body)

    def admitted(route, result, want_tenant, why):
        status, _h, text = result
        assert status == 200, f"/{route} {why}: expected 200 from the integration, got {status}: {text!r}"
        assert json.loads(text) == {"ran": route, "tenant": want_tenant}, (
            f"/{route} {why}: the integration must have run, got {text!r}")

    def refused(route, result, message, why):
        status, headers, text = result
        assert status == 400, f"/{route} {why}: expected 400, got {status}: {text!r}"
        assert json.loads(text) == {"message": message}, (
            f"/{route} {why}: expected {{'message': {message!r}}}, got {text!r}")
        assert headers.get("x-amzn-errortype") == "BadRequestException", (
            f"/{route} {why}: expected BadRequestException, got {headers.get('x-amzn-errortype')!r}")
        assert "ran" not in text, f"/{route} {why}: the integration ran: {text!r}"

    # Positive control on every route: a fully valid request is served.
    for route in modes:
        _poll(lambda r=route: post(r, good), lambda res: res[0] == 200, f"POST /{route}")
        admitted(route, post(route, good), tenant, "valid request")

    # body-only: validates the body, ignores the missing parameter.
    refused("body", post("body", bad_min), _BAD_BODY, "qty below minimum")
    refused("body", post("body", bad_missing), _BAD_BODY, "sku missing")
    admitted("body", post("body", good, with_tenant=False), "", "tenant missing, body-only validator")

    # params-only: validates the parameter, ignores the bad body.
    refused("params", post("params", good, with_tenant=False), _BAD_PARAMS, "tenant missing")
    admitted("params", post("params", bad_min), tenant, "bad body, params-only validator")
    admitted("params", post("params", bad_missing), tenant, "sku missing, params-only validator")

    # both: each failure refused with its own message.
    refused("both", post("both", bad_min), _BAD_BODY, "qty below minimum")
    refused("both", post("both", good, with_tenant=False), _BAD_PARAMS, "tenant missing")
    status, headers, text = post("both", bad_min, with_tenant=False)
    assert status == 400 and json.loads(text).get("message") in (_BAD_BODY, _BAD_PARAMS), (
        f"/both with BOTH failures must be refused by one of the two validations, got "
        f"{status}: {text!r}")
    assert "ran" not in text, f"/both with both failures ran the integration: {text!r}"

    # none: the same declarations without a validator are not enforced at all.
    admitted("none", post("none", bad_min), tenant, "bad body, no validator")
    admitted("none", post("none", good, with_tenant=False), "", "tenant missing, no validator")


_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-xsvc"}


def _xname(ctx, kind):
    return ctx.unique_name(f"sim2real-xsvc-{kind}-")


def _c(fn, **kw):
    """Call an apigateway control-plane op, retrying only its per-account mutation throttle."""
    for attempt in range(10):
        try:
            return fn(**kw)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "TooManyRequestsException" or attempt == 9:
                raise
            time.sleep(min(4.0, 0.3 * (2 ** attempt)))
    raise RuntimeError("unreachable")


def _poll(probe, predicate, description, timeout_s=150.0, interval_s=3.0):
    """Poll probe() to a condition (stage propagation), tolerating connection errors while
    execute-api DNS settles."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        try:
            last = probe()
        except OSError as exc:
            last = ("connection error", {}, repr(exc))
        else:
            if predicate(last):
                return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description}: condition not met within {timeout_s}s; last {last!r}")
        time.sleep(interval_s)


def _raw_request(method, url, header_pairs, body=None):
    """HTTP via http.client; returns (status, lower-cased headers, text). A 4xx/5xx is a
    result, not an exception."""
    u = urllib.parse.urlsplit(url)
    conn_cls = http.client.HTTPSConnection if u.scheme == "https" else http.client.HTTPConnection
    conn = conn_cls(u.netloc, timeout=25)
    try:
        conn.putrequest(method, u.path + (f"?{u.query}" if u.query else ""),
                        skip_accept_encoding=True)
        for k, v in header_pairs:
            conn.putheader(k, v)
        if body is not None:
            conn.putheader("Content-Length", str(len(body)))
        conn.endheaders()
        if body is not None:
            conn.send(body)
        resp = conn.getresponse()
        return (resp.status, {k.lower(): v for k, v in resp.getheaders()},
                resp.read().decode("utf-8", "replace"))
    finally:
        conn.close()


def _rest_invoke_url(ctx, api_id, stage, path):
    p = path.lstrip("/")
    return f"{ctx.rest_api_url(api_id, stage)}/{p}"


def _create_rest_api(ctx, kind, **extra):
    ag = ctx.client("apigateway")
    api_id = _c(ag.create_rest_api, name=_xname(ctx, kind), description=f"sim2real {CHECK}",
                endpointConfiguration={"types": ["REGIONAL"]}, tags=dict(_TAGS), **extra)["id"]
    ctx.on_cleanup(lambda: _c(ag.delete_rest_api, restApiId=api_id))
    root_id = next(r["id"] for r in ag.get_resources(restApiId=api_id)["items"] if r["path"] == "/")
    return api_id, root_id


def _deploy_stage(ctx, api_id, stage, variables=None):
    ag = ctx.client("apigateway")
    dep_id = _c(ag.create_deployment, restApiId=api_id)["id"]
    kw = {"restApiId": api_id, "stageName": stage, "deploymentId": dep_id}
    if variables:
        kw["variables"] = variables
    _c(ag.create_stage, **kw)
    ctx.on_cleanup(lambda: _c(ag.delete_stage, restApiId=api_id, stageName=stage))
    return dep_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
