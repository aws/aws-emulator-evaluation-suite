"""apigw-header-parameter-required-rejected-case-insensitive-match."""
from __future__ import annotations

import random
import string
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "apigw-header-parameter-required-rejected-case-insensitive-match"
GROUP = "parameter-validation"
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


def _http(method, url, headers=None, *, verify=True):
    """(status, text) for one request whose header names go on the wire EXACTLY as given.

    ``http.client.putheader`` sends a name verbatim, unlike ``urllib.request``, which
    capitalizes it -- so ``X-Required`` and ``x-required`` really are two different casings.
    """
    import http.client
    import urllib.parse

    u = urllib.parse.urlsplit(url)
    if u.scheme == "https":
        conn = http.client.HTTPSConnection(u.hostname, u.port or 443, timeout=15,
                                           context=_ssl_context(verify))
    else:
        conn = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=15)
    try:
        conn.putrequest(method, (u.path or "/") + (f"?{u.query}" if u.query else ""))
        for name, value in (headers or {}).items():
            conn.putheader(name, value)
        conn.endheaders()
        resp = conn.getresponse()
        return resp.status, resp.read().decode()
    finally:
        conn.close()


def _poll(url, headers, predicate, *, verify=True, timeout_s=150.0, interval_s=3.0,
          description="stage response"):
    deadline = time.monotonic() + timeout_s
    while True:
        status, text = _http("GET", url, headers=headers, verify=verify)
        if predicate(status, text):
            return status, text
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not observed within {timeout_s}s; last=({status}, {text[:300]!r})")
        time.sleep(interval_s)


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A required header request parameter behind a validateRequestParameters validator answers 400
    "Missing required request parameters: [X-Required]" without invoking the integration when absent,
    while the same header in another case ('x-required') satisfies it and reaches the integration."""
    ag = ctx.client("apigateway")
    marker = f"sim2real-{_unique_token()}"

    api_id = _retry_throttled(lambda: ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK},
    ))["id"]
    ctx.on_cleanup(lambda: _delete_rest_api(ag, api_id))

    validator_id = _retry_throttled(lambda: ag.create_request_validator(
        restApiId=api_id, name=ctx.unique_name("sim2real-behav-validator-"),
        validateRequestParameters=True, validateRequestBody=False,
    ))["id"]
    resource_id = _retry_throttled(lambda: ag.create_resource(
        restApiId=api_id, parentId=_root_id(ag, api_id), pathPart="needs"
    ))["id"]
    _retry_throttled(lambda: ag.put_method(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET",
        authorizationType="NONE", requestValidatorId=validator_id,
        requestParameters={"method.request.header.X-Required": True},
    ))
    _retry_throttled(lambda: ag.put_integration(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode":200}'},
    ))
    _retry_throttled(lambda: ag.put_method_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200",
    ))
    _retry_throttled(lambda: ag.put_integration_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200",
        selectionPattern="",
        responseTemplates={"application/json": '{"integration_marker":"%s"}' % marker},
    ))

    stage = ctx.unique_name("s").replace("-", "")[:20]
    _retry_throttled(lambda: ag.create_deployment(restApiId=api_id, stageName=stage))
    ctx.on_cleanup(lambda: ag.delete_stage(restApiId=api_id, stageName=stage))
    url = f"{ctx.rest_api_url(api_id, stage)}/needs"

    status, text = _poll(
        url, None, lambda s, t: s in (200, 400), verify=ctx.http_verify,
        description="deployment to become servable",
    )
    assert status == 400, f"expected 400 with the header absent, got {status}: {text[:300]!r}"
    assert text == '{"message": "Missing required request parameters: [X-Required]"}', (
        f"unexpected rejection body: {text!r}"
    )
    assert marker not in text, (
        f"the integration's own marker must never appear in a validator rejection; body was {text!r}"
    )

    status_ok, text_ok = _http("GET", url, headers={"X-Required": "present"}, verify=ctx.http_verify)
    assert status_ok == 200, f"declared-case header expected 200, got {status_ok}: {text_ok[:300]!r}"
    assert marker in text_ok, f"the integration must have run; body was {text_ok!r}"

    status_lower, text_lower = _http(
        "GET", url, headers={"x-required": "present-lowercase"}, verify=ctx.http_verify
    )
    assert status_lower == 200, (
        f"a header matching by name only, under different case, must satisfy the requirement and "
        f"reach the integration; got {status_lower}: {text_lower[:300]!r}"
    )
    assert marker in text_lower, (
        f"the integration must have run for the lower-cased header too; body was {text_lower!r}"
    )

    # A second parameterless request must be rejected identically -- not a one-shot cold-path hit.
    status2, text2 = _http("GET", url, verify=ctx.http_verify)
    assert status2 == 400, f"second parameterless request expected 400, got {status2}: {text2[:300]!r}"
    assert text2 == '{"message": "Missing required request parameters: [X-Required]"}', (
        f"unexpected second rejection body: {text2!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
