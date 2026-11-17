"""import-api-malformed-body-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "import-api-malformed-body-rejected"
GROUP = "error-semantics"
SERVICES = ["apigatewayv2"]


def _error(fn):
    """(code, message) of the ClientError fn() raised. An unexpected success RAISES."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ImportApi with a body that is not valid JSON is refused with BadRequestException and
    creates no API; a minimal valid OpenAPI document in the same shape imports successfully.
    """
    agw = ctx.client("apigatewayv2")
    name = ctx.unique_name("sim2real-behav-importapi-")

    code, message = _error(lambda: agw.import_api(Body="{not valid json"))
    assert code == "BadRequestException", (
        f"ImportApi with a malformed body: expected BadRequestException, got {code}: {message!r}"
    )
    assert message == (
        "Unable to build importer with provided input. Unable to determine OAS version"
    ), f"unexpected message {message!r}"

    own_before = [a["Name"] for a in agw.get_apis().get("Items", []) if a["Name"] == name]
    assert own_before == [], (
        f"the refused ImportApi must not have minted an API named {name!r}, got {own_before!r}"
    )

    spec = {
        "openapi": "3.0.1",
        "info": {"title": name, "version": "1.0"},
        "paths": {
            "/probe": {
                "get": {"responses": {"200": {"description": "ok"}}},
            }
        },
    }
    imported = agw.import_api(Body=json.dumps(spec))
    api_id = imported["ApiId"]
    ctx.on_cleanup(lambda: agw.delete_api(ApiId=api_id))
    assert imported.get("Name") == name, (
        f"a well-formed OpenAPI document must import with the title as Name: expected {name!r}, "
        f"got {imported.get('Name')!r}"
    )

    routes = [r["RouteKey"] for r in agw.get_routes(ApiId=api_id)["Items"]]
    assert routes == ["GET /probe"], (
        f"the imported API must carry the one route the document declared, got {routes!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
