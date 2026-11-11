"""apigw-integration-response-parameters-evaluate-context-api-account-and-route-vars."""
from __future__ import annotations

import random
import string
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "apigw-integration-response-parameters-evaluate-context-api-account-and-route-vars"
GROUP = "parameter-mapping"
SERVICES = ["apigateway"]


def _unique_token(length=10):
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


def _retry_throttled(fn, *, attempts=10):
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "TooManyRequestsException":
                raise
            if attempt == attempts - 1:
                raise
            time.sleep(min(4.0, 0.2 * (2 ** attempt)) + random.uniform(0, 0.2))


def _root_id(ag, api_id):
    for item in ag.get_resources(restApiId=api_id)["items"]:
        if item.get("path") == "/":
            return item["id"]
    raise AssertionError(f"root resource not found on {api_id!r}")


def _delete_rest_api(ag, api_id, *, budget_s=150.0):
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
                raise
        time.sleep(delay)
        delay = min(delay * 2, 30.0)


def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    import ssl

    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _http_get(url, *, verify=True, timeout=15):
    import urllib.error
    import urllib.request

    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_context(verify)) as resp:
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}
    except urllib.error.HTTPError as exc:
        return exc.code, {k.lower(): v for k, v in (exc.headers or {}).items()}


def _poll(url, predicate, *, verify=True, timeout_s=150.0, interval_s=3.0,
          description="stage response"):
    deadline = time.monotonic() + timeout_s
    while True:
        status, headers = _http_get(url, verify=verify)
        if predicate(status, headers):
            return status, headers
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not observed within {timeout_s}s; last status={status}")
        time.sleep(interval_s)


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """Integration-response header parameters evaluate $context.apiId, accountId, domainName,
    resourcePath and httpMethod to this API, account and route, and $context.path (stage segment
    included) differs from $context.resourcePath (the resource template, stage segment excluded)."""
    ag = ctx.client("apigateway")
    api_id = _retry_throttled(lambda: ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK},
    ))["id"]
    ctx.on_cleanup(lambda: _delete_rest_api(ag, api_id))

    resource_id = _retry_throttled(lambda: ag.create_resource(
        restApiId=api_id, parentId=_root_id(ag, api_id), pathPart="ctxvars"
    ))["id"]
    _retry_throttled(lambda: ag.put_method(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", authorizationType="NONE",
    ))
    _retry_throttled(lambda: ag.put_integration(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    ))
    names = ("X-Api-Id", "X-Account-Id", "X-Domain", "X-Path", "X-Protocol", "X-Resource-Path", "X-Http-Method")
    _retry_throttled(lambda: ag.put_method_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200",
        responseParameters={f"method.response.header.{n}": False for n in names},
    ))
    _retry_throttled(lambda: ag.put_integration_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200",
        selectionPattern="",
        responseParameters={
            "method.response.header.X-Api-Id": "context.apiId",
            "method.response.header.X-Account-Id": "context.accountId",
            "method.response.header.X-Domain": "context.domainName",
            "method.response.header.X-Path": "context.path",
            "method.response.header.X-Protocol": "context.protocol",
            "method.response.header.X-Resource-Path": "context.resourcePath",
            "method.response.header.X-Http-Method": "context.httpMethod",
        },
        responseTemplates={"application/json": '{"ok":true}'},
    ))

    stage = ctx.unique_name("s").replace("-", "")[:20]
    _retry_throttled(lambda: ag.create_deployment(restApiId=api_id, stageName=stage))
    ctx.on_cleanup(lambda: ag.delete_stage(restApiId=api_id, stageName=stage))
    url = f"{ctx.rest_api_url(api_id, stage)}/ctxvars"

    status, headers = _poll(
        url, lambda s, h: s == 200, verify=ctx.http_verify, description="GET to be served"
    )
    assert status == 200, f"expected 200, got {status}"

    assert headers.get("x-api-id") == api_id, f"context.apiId was {headers.get('x-api-id')!r}, expected {api_id!r}"
    assert headers.get("x-account-id") == ctx.account, (
        f"context.accountId was {headers.get('x-account-id')!r}, expected {ctx.account!r}"
    )
    domain = headers.get("x-domain")
    assert domain, f"context.domainName was empty or absent; headers were {headers!r}"
    domain_mismatch = ctx.published_url_mismatch(
        ctx.endpoint_url(domain), labels=(api_id, "execute-api", ctx.region)
    )
    assert domain_mismatch is None, (
        f"context.domainName was {headers.get('x-domain')!r}: {domain_mismatch}"
    )
    assert headers.get("x-protocol") == "HTTP/1.1", f"context.protocol was {headers.get('x-protocol')!r}"
    assert headers.get("x-http-method") == "GET", f"context.httpMethod was {headers.get('x-http-method')!r}"

    assert headers.get("x-resource-path") == "/ctxvars", (
        f"context.resourcePath must be the resource's own template with no stage segment; "
        f"got {headers.get('x-resource-path')!r}"
    )
    assert headers.get("x-path") == f"/{stage}/ctxvars", (
        f"context.path must be the full matched path INCLUDING the stage segment, unlike "
        f"resourcePath; got {headers.get('x-path')!r}, expected {'/' + stage + '/ctxvars'!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
