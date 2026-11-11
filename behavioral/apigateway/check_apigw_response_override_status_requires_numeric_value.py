"""apigw-response-override-status-requires-numeric-value."""
from __future__ import annotations

import random
import string
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "apigw-response-override-status-requires-numeric-value"
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
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, {k.lower(): v for k, v in (exc.headers or {}).items()}, exc.read().decode()


def _poll(url, predicate, *, verify=True, timeout_s=150.0, interval_s=3.0,
          description="stage response"):
    deadline = time.monotonic() + timeout_s
    while True:
        status, headers, text = _http_get(url, verify=verify)
        if predicate(status, headers, text):
            return status, headers, text
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} not observed within {timeout_s}s; last=({status}, {text[:300]!r})"
            )
        time.sleep(interval_s)


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A MOCK integration response declared 200 is served as 201 when its template sets
    $context.responseOverride.status to a numeric literal and stays 200 when it sets the string "201",
    while a responseOverride header set to a plain string is served either way."""
    ag = ctx.client("apigateway")
    api_id = _retry_throttled(lambda: ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK},
    ))["id"]
    ctx.on_cleanup(lambda: _delete_rest_api(ag, api_id))

    resource_id = _retry_throttled(lambda: ag.create_resource(
        restApiId=api_id, parentId=_root_id(ag, api_id), pathPart="ov"
    ))["id"]
    _retry_throttled(lambda: ag.put_method(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", authorizationType="NONE",
    ))
    _retry_throttled(lambda: ag.put_integration(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    ))
    _retry_throttled(lambda: ag.put_method_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200",
        responseParameters={"method.response.header.X-Overridden": False},
    ))
    _retry_throttled(lambda: ag.put_method_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="201",
    ))
    numeric_template = (
        "#set($context.responseOverride.status = 201)\n"
        "#set($context.responseOverride.header.X-Overridden = \"numeric-literal\")\n"
        '{"served":true}'
    )
    _retry_throttled(lambda: ag.put_integration_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200",
        selectionPattern="", responseTemplates={"application/json": numeric_template},
    ))

    stage = ctx.unique_name("s").replace("-", "")[:20]
    _retry_throttled(lambda: ag.create_deployment(restApiId=api_id, stageName=stage))
    ctx.on_cleanup(lambda: ag.delete_stage(restApiId=api_id, stageName=stage))
    base_url = ctx.rest_api_url(api_id, stage) + "/ov"

    status, headers, text = _poll(
        base_url, lambda s, h, t: s in (200, 201), verify=ctx.http_verify,
        description="GET to be served",
    )
    assert status == 201, (
        f"a numeric literal assigned to $context.responseOverride.status must override the "
        f"declared statusCode 200 to 201; got {status}: {text[:300]!r}"
    )
    assert text == '{"served":true}', f"body was {text!r}"
    assert headers.get("x-overridden") == "numeric-literal", (
        f"responseOverride.header must be honoured alongside the status override; got "
        f"{headers.get('x-overridden')!r}"
    )

    string_template = (
        "#set($context.responseOverride.status = \"201\")\n"
        "#set($context.responseOverride.header.X-Overridden = \"string-literal\")\n"
        '{"served":true}'
    )
    _retry_throttled(lambda: ag.put_integration_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200",
        selectionPattern="", responseTemplates={"application/json": string_template},
    ))
    # A deployed stage serves the SNAPSHOT taken at deployment time, not live config -- the
    # edit above needs a fresh deployment to the same stage before it is ever reachable.
    _retry_throttled(lambda: ag.create_deployment(restApiId=api_id, stageName=stage))

    status2, headers2, text2 = _poll(
        base_url,
        lambda s, h, t: h.get("x-overridden") == "string-literal",
        verify=ctx.http_verify,
        description="redeployed integration response to take effect",
    )
    assert status2 == 200, (
        f"the quoted STRING literal \"201\" assigned to responseOverride.status must leave the "
        f"declared statusCode 200 untouched, even though it spells a valid status number; got "
        f"{status2}: {text2[:300]!r}"
    )
    assert text2 == '{"served":true}', f"body was {text2!r}"
    assert headers2.get("x-overridden") == "string-literal", (
        f"responseOverride.header assignment from a plain string must still take effect even "
        f"when the status assignment on the same request did not; got {headers2.get('x-overridden')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
