"""apigw-put-rest-api-warnings-transient-and-strict-overwrite-preserves-state."""
from __future__ import annotations

import json
import random
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "apigw-put-rest-api-warnings-transient-and-strict-overwrite-preserves-state"
GROUP = 'rest-api'
SERVICES = ['apigateway']


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


def _error_code(fn):
    """Call fn(); return (code, message) if a ClientError is raised.

    Raises when the call unexpectedly succeeds, rather than returning a falsy sentinel."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get(
            "Error", {}).get("Message", "")
    raise AssertionError(
        f"the call was expected to be REJECTED but it succeeded, returning {result!r}"
    )


def _mock_get(title, security=None):
    """A swagger 2.0 document with one MOCK-integrated GET /thing, optionally carrying a
    security requirement API Gateway cannot resolve to an authorizer."""
    op = {
        "responses": {"200": {"description": "ok"}},
        "x-amazon-apigateway-integration": {
            "type": "mock",
            "requestTemplates": {"application/json": '{"statusCode":200}'},
            "responses": {"default": {"statusCode": "200"}},
        },
    }
    if security:
        op["security"] = security
    doc = {
        "swagger": "2.0", "info": {"title": title, "version": "1.0"}, "basePath": "/",
        "paths": {"/thing": {"get": op}},
    }
    if security:
        doc["securityDefinitions"] = {"myAuth": {"type": "basic"}}
    return json.dumps(doc).encode()


def _warn_doc(title):
    """A document whose unresolvable 'basic' security scheme makes API Gateway emit a
    warning naming the security definition it could not resolve."""
    return _mock_get(title, security=[{"myAuth": []}])


def _clean_doc(title):
    return _mock_get(title)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """PutRestApi warnings appear only on the producing call, never on a later GetRestApi; with
    failOnWarnings=True the same document is rejected and the API's name and resources are unchanged.

    Reference: https://docs.aws.amazon.com/apigateway/latest/api/API_PutRestApi.html
    """
    ag = ctx.client("apigateway")
    base_title = ctx.unique_name("sim2real-behav-apigw-warn-")

    imported = _retry_throttled(lambda: ag.import_rest_api(
        body=_clean_doc(base_title), failOnWarnings=True,
    ))
    api_id = imported["id"]
    ctx.on_cleanup(lambda: _retry_throttled(lambda: ag.delete_rest_api(restApiId=api_id)))
    _retry_throttled(lambda: ag.tag_resource(
        resourceArn=f"arn:aws:apigateway:{ctx.region}::/restapis/{api_id}",
        tags={"sim2real": CHECK}))
    assert not imported.get("warnings"), (
        f"a clean document must import with no warnings, got {imported.get('warnings')!r}"
    )

    overwrite_title = ctx.unique_name("sim2real-behav-apigw-warn-ov-")
    overwritten = _retry_throttled(lambda: ag.put_rest_api(
        restApiId=api_id, mode="overwrite", failOnWarnings=False,
        body=_warn_doc(overwrite_title),
    ))
    warnings = overwritten.get("warnings") or []
    want_warnings = [
        "Unsupported security definition type 'basic' for 'myAuth'. Ignoring.",
        "Method 'GET' on resource '/thing' specified security, but no custom authorizers were "
        "created and the extension x-amazon-apigateway-auth was not properly set. This method "
        "will be not be secured.",
    ]
    assert warnings == want_warnings, (
        f"expected the warning naming the unresolved security definition {want_warnings!r}, "
        f"got {warnings!r}"
    )

    readback = _retry_throttled(lambda: ag.get_rest_api(restApiId=api_id))
    assert not readback.get("warnings"), (
        f"GetRestApi must never echo back a prior call's warnings — got "
        f"{readback.get('warnings')!r} immediately after a call that returned {warnings!r}"
    )

    before_name = readback["name"]
    before_resources = sorted(
        r["path"] for r in _retry_throttled(lambda: ag.get_resources(restApiId=api_id))["items"]
    )

    code, message = _error_code(lambda: ag.put_rest_api(
        restApiId=api_id, mode="overwrite", failOnWarnings=True,
        body=_warn_doc(overwrite_title),
    ))
    want_message = "Warnings found during import:\n" + "\n".join(f"\t{w}" for w in want_warnings)
    assert (code, message) == ("BadRequestException", want_message), (
        f"expected BadRequestException {want_message!r} from failOnWarnings over an unresolved "
        f"security definition, got {code!r}: {message!r}"
    )

    after = _retry_throttled(lambda: ag.get_rest_api(restApiId=api_id))
    after_resources = sorted(
        r["path"] for r in _retry_throttled(lambda: ag.get_resources(restApiId=api_id))["items"]
    )
    assert after["name"] == before_name, (
        f"a REJECTED overwrite changed the API's name from {before_name!r} to "
        f"{after['name']!r}"
    )
    assert after_resources == before_resources, (
        f"a REJECTED overwrite changed the resource tree from {before_resources!r} to "
        f"{after_resources!r}"
    )

    # Positive control: the API is not bricked — a clean document still overwrites fine.
    clean_title = ctx.unique_name("sim2real-behav-apigw-warn-clean-")
    recovered = _retry_throttled(lambda: ag.put_rest_api(
        restApiId=api_id, mode="overwrite", failOnWarnings=True,
        body=_clean_doc(clean_title),
    ))
    assert not recovered.get("warnings"), (
        f"a clean overwrite after a rejected one must still succeed with no warnings, "
        f"got {recovered.get('warnings')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
