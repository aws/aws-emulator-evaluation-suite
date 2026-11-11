"""apigw-import-rest-api-fail-on-warnings-rejects-and-leaves-no-api-behind."""
from __future__ import annotations

import json
import random
import string
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "apigw-import-rest-api-fail-on-warnings-rejects-and-leaves-no-api-behind"
GROUP = 'rest-api'
SERVICES = ['apigateway']


def _unique_token(length=10):
    """Lowercase alphanumeric token (apigateway stage names reject hyphens)."""
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


def _error_code(fn):
    """Call fn(); return the botocore Error (Code, Message) if a ClientError is raised.

    An unexpected success raises, so an accepted import is reported as accepted rather than
    as a wrong error code."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get(
            "Error", {}).get("Message", "")
    raise AssertionError(
        f"the call was expected to be REJECTED but it succeeded, returning {result!r}"
    )


def _all_rest_apis(ag):
    """Every REST API in the account, fully paginated.

    The account may already hold other APIs that push a page-one membership assertion off
    the page, and the claim here is about the WHOLE inventory."""
    items = []
    for page in ag.get_paginator("get_rest_apis").paginate():
        items.extend(page.get("items", []))
    return items


def _retry_throttled(fn, *, attempts=10):
    """Call fn(), retrying only TooManyRequestsException with jittered backoff."""
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "TooManyRequestsException":
                raise
            if attempt == attempts - 1:
                raise
            time.sleep(min(4.0, 0.2 * (2 ** attempt)) + random.uniform(0, 0.2))


def _http(method, url, body=None, headers=None):
    """HTTP request; returns (status, lowercased response headers, body text)."""
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310 - fixed https
            return (resp.status, {k.lower(): v for k, v in resp.headers.items()},
                    resp.read().decode())
    except urllib.error.HTTPError as exc:
        return (exc.code, {k.lower(): v for k, v in (exc.headers or {}).items()},
                exc.read().decode())


def _apigw_url(ctx, api_id, stage, path=""):
    """Invoke URL for a path on a deployed stage."""
    return f"{ctx.rest_api_url(api_id, stage)}/{path.lstrip('/')}"


def _poll_http(url, predicate, *, method="GET", body=None, headers=None,
               timeout_s=150.0, interval_s=3.0, description="stage response"):
    """Re-issue an HTTP request until predicate(status, headers, text) holds, bounded."""
    deadline = time.monotonic() + timeout_s
    while True:
        status, resp_headers, text = _http(method, url, body=body, headers=headers)
        if predicate(status, resp_headers, text):
            return status, resp_headers, text
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} not observed within {timeout_s}s; last=({status}, {text!r})"
            )
        time.sleep(interval_s)


def _openapi(title):
    """A MOCK POST /imported whose response schema $refs an undefined model: ImportRestApi treats
    that as a warning (in a requestBody it would be a hard error), so failOnWarnings alone decides
    the outcome."""
    return json.dumps({
        "openapi": "3.0.1",
        "info": {"title": title, "version": "1.0"},
        "paths": {"/imported": {"post": {
            "responses": {"200": {
                "description": "ok",
                "content": {"application/json": {
                    "schema": {"$ref": "#/components/schemas/Item"}}},
            }},
            "x-amazon-apigateway-integration": {
                "type": "mock",
                "requestTemplates": {"application/json": '{"statusCode":200}'},
                "responses": {"default": {
                    "statusCode": "200",
                    "responseTemplates": {
                        "application/json": '{"imported":true,"title":"%s"}' % title},
                }},
            },
        }}},
        "components": {"schemas": {}},
    }).encode()


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:control",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """ImportRestApi with failOnWarnings=True on an OpenAPI document with one dangling $ref fails with
    BadRequestException and leaves the account's REST API list unchanged, while the identical document
    imported without the flag succeeds, deploys and serves its route over HTTP."""
    ag = ctx.client("apigateway")

    title = ctx.unique_name("sim2real-behav-apigw-import-")
    document = _openapi(title)
    before = {a["id"] for a in _all_rest_apis(ag)}
    assert title not in {a.get("name") for a in _all_rest_apis(ag)}, (
        f"precondition: the unique title {title!r} must not already exist in the account"
    )

    code, message = _error_code(lambda: ag.import_rest_api(
        body=document, failOnWarnings=True,
        parameters={"endpointConfigurationTypes": "REGIONAL"},
    ))
    assert code == "BadRequestException", (
        f"expected BadRequestException from failOnWarnings over a dangling $ref, got "
        f"{code!r}: {message!r}"
    )
    expected_message = (
        "Warnings found during import:\n"
        "\tReference to model 'Item' not found. Ignoring.\n"
        "\tReference to model 'Item' not found. Ignoring.\n"
        "\tInvalid format for model application/json for method POST"
    )
    assert message == expected_message, (
        f"the rejection must name the warning it refused to tolerate, got {message!r}"
    )

    after = {a["id"] for a in _all_rest_apis(ag)}
    titles_after = {a.get("name") for a in _all_rest_apis(ag)}
    assert title not in titles_after, (
        f"a REST API named {title!r} survived the REJECTED import — failOnWarnings must "
        f"leave nothing behind"
    )
    assert after == before, (
        f"the account's REST API inventory changed across a rejected import; appeared: "
        f"{sorted(after - before)!r}, disappeared: {sorted(before - after)!r}"
    )

    # Positive control: the SAME bytes, without the flag, import AND serve.
    imported = _retry_throttled(lambda: ag.import_rest_api(
        body=document,
        parameters={"endpointConfigurationTypes": "REGIONAL"},
    ))
    api_id = imported["id"]
    ctx.on_cleanup(lambda: _retry_throttled(lambda: ag.delete_rest_api(restApiId=api_id)))
    assert imported.get("name") == title, (
        f"the corrected document must import as {title!r}, got {imported.get('name')!r}"
    )

    deployment_id = _retry_throttled(lambda: ag.create_deployment(restApiId=api_id))["id"]
    _retry_throttled(lambda: ag.create_stage(
        restApiId=api_id, stageName="test", deploymentId=deployment_id,
        tags={"sim2real": "import-fail-on-warnings"},
    ))
    ctx.on_cleanup(lambda: _retry_throttled(
        lambda: ag.delete_stage(restApiId=api_id, stageName="test")))

    url = _apigw_url(ctx, api_id, "test", "/imported")
    status, _h, text = _poll_http(
        url, lambda s, h, t: s == 200, method="POST",
        body=json.dumps({"name": "sim2real"}).encode(),
        headers={"Content-Type": "application/json"},
        description=f"POST {url} on the imported API to be served",
    )
    assert status == 200, (
        f"the imported route did not serve: {status!r} {text!r}"
    )
    payload = json.loads(text)
    assert payload == {"imported": True, "title": title}, (
        f"the imported API must serve the mock integration the document declared, got "
        f"{payload!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
