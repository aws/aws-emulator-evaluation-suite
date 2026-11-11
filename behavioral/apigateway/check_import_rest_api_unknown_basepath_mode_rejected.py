"""import-rest-api-unknown-basepath-mode-rejected."""
from __future__ import annotations

import json
import random
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "import-rest-api-unknown-basepath-mode-rejected"
GROUP = "negative-classes"
SERVICES = ["apigateway"]


def _retry_throttled(fn, *, attempts=10):
    """Call fn(), retrying only TooManyRequestsException with jittered backoff.

    The apigateway control plane rate-limits mutating calls per account, so
    other activity in the same account can surface as a throttle unrelated to the claim."""
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "TooManyRequestsException":
                raise
            if attempt == attempts - 1:
                raise
            time.sleep(min(4.0, 0.2 * (2 ** attempt)) + random.uniform(0, 0.2))


def _doc(title):
    return {
        "swagger": "2.0",
        "info": {"title": title, "version": "1.0"},
        "basePath": "/v1",
        "schemes": ["https"],
        "paths": {
            "/pets": {
                "get": {
                    "responses": {"200": {"description": "OK"}},
                    "x-amazon-apigateway-integration": {
                        "type": "MOCK",
                        "requestTemplates": {"application/json": '{"statusCode": 200}'},
                        "responses": {"default": {"statusCode": "200"}},
                    },
                }
            }
        },
    }


_UNKNOWN_BASEPATH = ("BadRequestException", "Unrecognized base path option: wrap")


def expect_error(fn, code, message, undo=None):
    """Assert ``fn()`` raises exactly ``(code, message)``.

    On an unexpected success ``undo(result)`` registers the cleanup before the failure is raised.
    """
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    if undo is not None:
        undo(result)
    raise AssertionError(f"expected {(code, message)!r}, but the call succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ImportRestApi rejects a `basepath` parameter outside ignore/prepend/split, and the
    document still imports cleanly with one of the documented values (positive control).

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-import-api-basePath.html
    """
    apigw = ctx.client("apigateway")

    title = ctx.unique_name("sim2real-behav-apigw-bp-bad-")
    expect_error(
        lambda: apigw.import_rest_api(
            body=json.dumps(_doc(title)).encode("utf-8"),
            parameters={"basepath": "wrap"},
        ),
        *_UNKNOWN_BASEPATH,
        undo=lambda created: ctx.on_cleanup(
            lambda: _retry_throttled(lambda: apigw.delete_rest_api(restApiId=created["id"]))),
    )

    # Positive control: the very same document imports under a documented mode.
    control_title = ctx.unique_name("sim2real-behav-apigw-bp-ok-")
    created = _retry_throttled(lambda: apigw.import_rest_api(
        body=json.dumps(_doc(control_title)).encode("utf-8"),
        parameters={"basepath": "ignore"},
    ))
    api_id = created["id"]
    ctx.on_cleanup(lambda: _retry_throttled(lambda: apigw.delete_rest_api(restApiId=api_id)))
    resources = apigw.get_resources(restApiId=api_id)["items"]
    paths = {r["path"] for r in resources}
    assert paths == {"/", "/pets"}, (
        f"positive control: basepath=ignore must import the document without its basePath, "
        f"got {sorted(paths)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
