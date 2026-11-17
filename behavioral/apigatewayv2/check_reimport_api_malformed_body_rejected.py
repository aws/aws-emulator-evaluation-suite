"""reimport-api-malformed-body-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "reimport-api-malformed-body-rejected"
GROUP = "import-export"
SERVICES = ["apigatewayv2"]

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


def _mock_spec(route_path: str) -> dict:
    return {
        "openapi": "3.0.1",
        "info": {"title": "sim2real-behav-reimport", "version": "1.0"},
        "paths": {
            route_path: {
                "get": {
                    "responses": {"200": {"description": "ok"}},
                    "x-amazon-apigateway-integration": {
                        "type": "MOCK",
                        "requestTemplates": {"application/json": '{"statusCode": 200}'},
                    },
                }
            }
        },
    }


def _error(fn):
    """(code, message) of the ClientError fn() raised. An unexpected success RAISES."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _route_keys(agw, api_id):
    return sorted(r["RouteKey"] for r in agw.get_routes(ApiId=api_id)["Items"])


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ReimportApi with a Body that is not valid JSON is rejected with BadRequestException and
    leaves the API's existing routes untouched; a well-formed Body still replaces them."""
    agw = ctx.client("apigatewayv2")

    imported = agw.import_api(Body=json.dumps(_mock_spec("/foo")))
    api_id = imported["ApiId"]
    ctx.on_cleanup(lambda: agw.delete_api(ApiId=api_id))
    assert _route_keys(agw, api_id) == ["GET /foo"], (
        f"ImportApi did not create the expected route, got {_route_keys(agw, api_id)!r}"
    )

    code, message = _error(lambda: agw.reimport_api(ApiId=api_id, Body="not valid json at all"))
    assert code == "BadRequestException", (
        f"ReimportApi with a non-JSON Body: expected BadRequestException, got {code}: {message!r}"
    )
    expected = "Unable to build importer with provided input. Unable to determine OAS version"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the API's routes are exactly what the original import created.
    assert _route_keys(agw, api_id) == ["GET /foo"], (
        f"the refused ReimportApi changed the API's routes: {_route_keys(agw, api_id)!r}"
    )

    # Positive control: a well-formed Body against the same API succeeds and fully replaces
    # the route set with the one the new document defines.
    agw.reimport_api(ApiId=api_id, Body=json.dumps(_mock_spec("/bar")))
    assert _route_keys(agw, api_id) == ["GET /bar"], (
        f"a well-formed ReimportApi did not replace the route set, got {_route_keys(agw, api_id)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
