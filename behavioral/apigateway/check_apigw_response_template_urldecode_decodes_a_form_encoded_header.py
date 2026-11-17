"""apigw-response-template-urldecode-decodes-a-form-encoded-header."""
from __future__ import annotations

import json
import secrets
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "apigw-response-template-urldecode-decodes-a-form-encoded-header"
GROUP = "mapping-templates"
SERVICES = ["apigateway"]

_HEADER = "x-form"
_ENCODED = "label=parcel+a%26weight%3D3%20kg"
_DECODED = "label=parcel a&weight=3 kg"
_REQUEST_TEMPLATE = '{"statusCode": 200}'
_RESPONSE_TEMPLATE = (
    '{"raw": "$util.escapeJavaScript($input.params(\'x-form\'))",'
    ' "decoded": "$util.escapeJavaScript($util.urlDecode($input.params(\'x-form\')))"}'
)


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


def _root(ag, api_id: str) -> str:
    """The id of the API's '/' resource."""
    for item in ag.get_resources(restApiId=api_id, limit=25)["items"]:
        if item["path"] == "/":
            return item["id"]
    raise AssertionError("the new API exposes no '/' resource to hang a path off")


def _endpoint(ctx, ag, api_id: str, segment: str, response_template: str) -> None:
    """A POST under /segment answered by MOCK, whose 200 renders response_template."""
    resource_id = _unthrottled(lambda: ag.create_resource(
        restApiId=api_id, parentId=_root(ag, api_id), pathPart=segment))["id"]
    ctx.on_cleanup(_undo(
        lambda: _unthrottled(
            lambda: ag.delete_resource(restApiId=api_id, resourceId=resource_id)),
        "NotFoundException",
    ))
    _unthrottled(lambda: ag.put_method(
        restApiId=api_id, resourceId=resource_id, httpMethod="POST", authorizationType="NONE",
        requestParameters={f"method.request.header.{_HEADER}": True}))
    _unthrottled(lambda: ag.put_integration(
        restApiId=api_id, resourceId=resource_id, httpMethod="POST", type="MOCK",
        passthroughBehavior="NEVER",
        requestTemplates={"application/json": _REQUEST_TEMPLATE}))
    _unthrottled(lambda: ag.put_method_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="POST", statusCode="200"))
    _unthrottled(lambda: ag.put_integration_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="POST", statusCode="200",
        selectionPattern="", responseTemplates={"application/json": response_template}))


def _submit(url: str):
    """(status, body text) of a POST carrying the encoded header; a transport error gives (None, repr)."""
    request = urllib.request.Request(
        url, data=b"{}", method="POST",
        headers={"Content-Type": "application/json", _HEADER: _ENCODED},
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as answer:  # noqa: S310 - https only
            return answer.status, answer.read().decode(errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode(errors="replace")
    except (urllib.error.URLError, OSError) as exc:
        return None, repr(exc)


def _served(url: str, *, budget_s: float = 180.0) -> str:
    """POST until the stage answers 200; raises on the deadline so a never-live stage fails loudly."""
    deadline = time.monotonic() + budget_s
    while True:
        status, text = _submit(url)
        if status == 200:
            return text
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"the stage never served POST {url} with 200 inside {budget_s}s; last answer was "
                f"{status!r} with body {text[:200]!r}"
            )
        time.sleep(4.0)


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A response mapping template's $util.urlDecode turns an application/x-www-form-urlencoded
    method request header into its decoded text, while the same template's untouched copy of that
    header shows the bytes arrived still percent-encoded.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-mapping-template-reference.html
    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/models-mappings.html
    """
    ag = ctx.client("apigateway")

    api_id = _unthrottled(lambda: ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-urldecode-"),
        description="sim2real urldecode mapping template",
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK},
    ))["id"]
    ctx.on_cleanup(_undo(lambda: _unthrottled(lambda: ag.delete_rest_api(restApiId=api_id)),
                         "NotFoundException"))

    _endpoint(ctx, ag, api_id, "decode", _RESPONSE_TEMPLATE)

    stage = "s" + secrets.token_hex(5)
    _unthrottled(lambda: ag.create_deployment(restApiId=api_id, stageName=stage))
    ctx.on_cleanup(_undo(
        lambda: _unthrottled(lambda: ag.delete_stage(restApiId=api_id, stageName=stage)),
        "NotFoundException",
    ))

    served = _served(f"{ctx.rest_api_url(api_id, stage)}/decode")
    rendered = json.loads(served)
    assert rendered.get("raw") == _ENCODED, (
        f"control: the template's untouched $input.params copy of the header must be the bytes "
        f"sent, {_ENCODED!r}, so the decoding below is the template's work and not the "
        f"transport's; the stage answered {served[:300]!r}"
    )
    assert rendered.get("decoded") == _DECODED, (
        f"$util.urlDecode must resolve the form encoding to {_DECODED!r} — '+' as a space and each "
        f"percent escape decoded; the stage answered {served[:300]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
