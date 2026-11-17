"""apigw-openapi-import-request-validator-extension-enforced-at-the-stage."""
from __future__ import annotations

import json
import secrets
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "apigw-openapi-import-request-validator-extension-enforced-at-the-stage"
GROUP = "request-validation"
SERVICES = ["apigateway"]

_STRICT_VALIDATOR = "parcelbody"
_LOOSE_VALIDATOR = "parcelparams"
_STRICT_OUTCOME = "parcel-stored"
_LOOSE_OUTCOME = "draft-stored"
_REFUSAL = "Invalid request body"


def _mock(outcome: str, validator: str | None) -> dict:
    """One OpenAPI POST operation: a body validated against the Parcel schema, answered by MOCK."""
    operation = {
        "requestBody": {
            "required": True,
            "content": {
                "application/json": {"schema": {"$ref": "#/components/schemas/Parcel"}}
            },
        },
        "responses": {
            "200": {
                "description": "stored",
                "content": {"application/json": {"schema": {"type": "object"}}},
            }
        },
        "x-amazon-apigateway-integration": {
            "type": "mock",
            "requestTemplates": {"application/json": '{"statusCode": 200}'},
            "responses": {
                "default": {
                    "statusCode": "200",
                    "responseTemplates": {
                        "application/json": '{"outcome": "%s"}' % outcome,
                    },
                }
            },
        },
    }
    if validator is not None:
        operation["x-amazon-apigateway-request-validator"] = validator
    return operation


def _definition(title: str) -> bytes:
    """An OpenAPI 3.0.1 definition whose API-level validator one method overrides."""
    return json.dumps(
        {
            "openapi": "3.0.1",
            "info": {"title": title, "version": "1.0.0"},
            "x-amazon-apigateway-request-validators": {
                _STRICT_VALIDATOR: {
                    "validateRequestBody": True,
                    "validateRequestParameters": False,
                },
                _LOOSE_VALIDATOR: {
                    "validateRequestBody": False,
                    "validateRequestParameters": True,
                },
            },
            "x-amazon-apigateway-request-validator": _STRICT_VALIDATOR,
            "paths": {
                "/parcels": {"post": _mock(_STRICT_OUTCOME, None)},
                "/drafts": {"post": _mock(_LOOSE_OUTCOME, _LOOSE_VALIDATOR)},
            },
            "components": {
                "schemas": {
                    "Parcel": {
                        "type": "object",
                        "required": ["weight", "label"],
                        "properties": {
                            "weight": {"type": "integer", "minimum": 1},
                            "label": {"type": "string"},
                        },
                    }
                }
            },
        }
    ).encode()


def _undo(delete, *gone: str):
    """A teardown that returns only on the resource's own not-found codes and raises otherwise."""

    def erase() -> None:
        try:
            delete()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in gone:
                return
            raise

    return erase


def _unthrottled(call, *, tries: int = 9):
    """call(), re-sent only while the apigateway control plane answers TooManyRequestsException."""
    for attempt in range(tries):
        try:
            return call()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "TooManyRequestsException":
                raise
            if attempt == tries - 1:
                raise
            time.sleep(min(5.0, 0.3 * 2**attempt))


def _validators(ag, api_id: str) -> dict:
    """Every request validator of one API, by name, read page by page."""
    found: dict = {}
    position = None
    while True:
        kwargs = {"restApiId": api_id, "limit": 25}
        if position is not None:
            kwargs["position"] = position
        page = ag.get_request_validators(**kwargs)
        for item in page.get("items", []):
            found[item["name"]] = item
        position = page.get("position")
        if not position:
            return found


def _resources(ag, api_id: str) -> dict:
    """Every resource of one API, by path, read page by page."""
    found: dict = {}
    position = None
    while True:
        kwargs = {"restApiId": api_id, "limit": 25}
        if position is not None:
            kwargs["position"] = position
        page = ag.get_resources(**kwargs)
        for item in page.get("items", []):
            found[item["path"]] = item["id"]
        position = page.get("position")
        if not position:
            return found


def _post(url: str, body: bytes):
    """(status, body text) of a POST of JSON; a transport error answers (None, repr)."""
    request = urllib.request.Request(
        url, data=body, method="POST", headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as answer:  # noqa: S310 - https only
            return answer.status, answer.read().decode(errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode(errors="replace")
    except (urllib.error.URLError, OSError) as exc:
        return None, repr(exc)


def _served(url: str, body: bytes, *, budget_s: float = 180.0):
    """POST until the stage answers 200; raises on the deadline so a never-live stage fails loudly."""
    deadline = time.monotonic() + budget_s
    while True:
        status, text = _post(url, body)
        if status == 200:
            return text
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"the imported stage never served POST {url} with 200 inside {budget_s}s; "
                f"last answer was {status!r} with body {text[:200]!r}"
            )
        time.sleep(4.0)


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes",
      "dp:endpoint", "plane:control", "plane:data")
def run(ctx) -> None:
    """An OpenAPI definition's x-amazon-apigateway-request-validators become real validators bound to
    the methods that name them, and the body-validating one refuses an incomplete body at the stage
    while the method that overrides it with a parameters-only validator serves the same bytes.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-swagger-extensions-request-validators.html
    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-request-validation-set-up.html
    """
    ag = ctx.client("apigateway")

    imported = _unthrottled(
        lambda: ag.import_rest_api(
            failOnWarnings=True,
            body=_definition(ctx.unique_name("sim2real-behav-apigw-reqval-")),
        )
    )
    api_id = imported["id"]
    ctx.on_cleanup(_undo(lambda: _unthrottled(lambda: ag.delete_rest_api(restApiId=api_id)),
                         "NotFoundException"))

    declared = _validators(ag, api_id)
    assert set(declared) == {_STRICT_VALIDATOR, _LOOSE_VALIDATOR}, (
        f"the import must create one validator per entry of the extension map; the API holds "
        f"{sorted(declared)!r}, expected {sorted((_STRICT_VALIDATOR, _LOOSE_VALIDATOR))!r}"
    )
    strict = declared[_STRICT_VALIDATOR]
    loose = declared[_LOOSE_VALIDATOR]
    assert (strict.get("validateRequestBody"), strict.get("validateRequestParameters")) == (
        True, False
    ), (
        f"validator {_STRICT_VALIDATOR!r} must carry body=True parameters=False as declared; got "
        f"body={strict.get('validateRequestBody')!r} "
        f"parameters={strict.get('validateRequestParameters')!r}"
    )
    assert (loose.get("validateRequestBody"), loose.get("validateRequestParameters")) == (
        False, True
    ), (
        f"validator {_LOOSE_VALIDATOR!r} must carry body=False parameters=True as declared; got "
        f"body={loose.get('validateRequestBody')!r} "
        f"parameters={loose.get('validateRequestParameters')!r}"
    )

    paths = _resources(ag, api_id)
    assert {"/parcels", "/drafts"} <= set(paths), (
        f"the import must build both declared paths; the API exposes {sorted(paths)!r}"
    )
    inherited = ag.get_method(restApiId=api_id, resourceId=paths["/parcels"], httpMethod="POST")
    assert inherited.get("requestValidatorId") == strict["id"], (
        f"POST /parcels names no validator of its own, so it must inherit the API-level "
        f"{_STRICT_VALIDATOR!r}; its requestValidatorId is "
        f"{inherited.get('requestValidatorId')!r}, which is not that validator's id"
    )
    overridden = ag.get_method(restApiId=api_id, resourceId=paths["/drafts"], httpMethod="POST")
    assert overridden.get("requestValidatorId") == loose["id"], (
        f"POST /drafts names {_LOOSE_VALIDATOR!r}, which must override the API-level validator; "
        f"its requestValidatorId is {overridden.get('requestValidatorId')!r}, which is not that "
        f"validator's id"
    )

    stage = "s" + secrets.token_hex(5)
    _unthrottled(lambda: ag.create_deployment(restApiId=api_id, stageName=stage))
    ctx.on_cleanup(_undo(
        lambda: _unthrottled(lambda: ag.delete_stage(restApiId=api_id, stageName=stage)),
        "NotFoundException",
    ))

    base = ctx.rest_api_url(api_id, stage)
    complete = json.dumps({"weight": 3, "label": "Example Corp parcel"}).encode()
    incomplete = json.dumps({"label": "Example Corp parcel"}).encode()

    accepted = _served(f"{base}/parcels", complete)
    assert json.loads(accepted) == {"outcome": _STRICT_OUTCOME}, (
        f"positive control: a body holding every required property must reach the integration and "
        f"return outcome {_STRICT_OUTCOME!r}; the stage answered {accepted[:200]!r}"
    )

    status, refused = _post(f"{base}/parcels", incomplete)
    assert status == 400, (
        f"a body missing the required 'weight' property must be refused 400 by the inherited "
        f"body validator; got {status!r} with body {refused[:200]!r}"
    )
    assert json.loads(refused) == {"message": _REFUSAL}, (
        f"the refusal must be the BAD_REQUEST_BODY gateway response {{'message': {_REFUSAL!r}}}; "
        f"got {refused[:200]!r}"
    )
    assert _STRICT_OUTCOME not in refused, (
        f"the validator refuses before the integration runs, so the refusal body must not carry "
        f"the integration outcome {_STRICT_OUTCOME!r}; got {refused[:200]!r}"
    )

    twin_status, twin = _post(f"{base}/drafts", incomplete)
    assert twin_status == 200, (
        f"twin control: the method whose only difference is a parameters-only validator must "
        f"serve the identical incomplete body; got {twin_status!r} with body {twin[:200]!r}"
    )
    assert json.loads(twin) == {"outcome": _LOOSE_OUTCOME}, (
        f"twin control: POST /drafts must reach the integration and return outcome "
        f"{_LOOSE_OUTCOME!r}, so the 400 above is the body validator and not the payload; the "
        f"stage answered {twin[:200]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
