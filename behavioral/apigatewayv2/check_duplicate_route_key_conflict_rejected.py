"""duplicate-route-key-conflict-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "duplicate-route-key-conflict-rejected"
GROUP = 'routing'
SERVICES = ['apigatewayv2']

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


def _err(fn):
    """Call fn(); return its ClientError (code, message, HTTP status). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message"), exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    raise AssertionError(
        f"expected ConflictException for a duplicate route key, but the call SUCCEEDED: "
        f"{result!r} (the emulator allowed two routes to share one key)"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A route key is unique per API: re-creating ``GET /dup`` is a ConflictException that leaves
    the original route in place, while ``POST /dup`` is a different key and is accepted.
    """
    agw = ctx.client("apigatewayv2")
    api = agw.create_api(
        Name=ctx.unique_name("sim2real-behav-httpapi-"), ProtocolType="HTTP", Tags=TAGS
    )
    api_id = api["ApiId"]
    ctx.on_cleanup(lambda: agw.delete_api(ApiId=api_id))
    integ_id = agw.create_integration(
        ApiId=api_id,
        IntegrationType="HTTP_PROXY",
        IntegrationUri="https://example.com/backend",
        IntegrationMethod="GET",
        PayloadFormatVersion="1.0",
    )["IntegrationId"]
    target = f"integrations/{integ_id}"
    original_id = agw.create_route(ApiId=api_id, RouteKey="GET /dup", Target=target)["RouteId"]

    code, message, status = _err(lambda: agw.create_route(ApiId=api_id, RouteKey="GET /dup", Target=target))
    assert code == "ConflictException", (
        f"expected ConflictException for a duplicate route key, got {code}: {message!r}"
    )
    assert status == 409, f"expected HTTP 409 for a duplicate route key, got {status!r}"
    expected_message = "Route with key GET /dup already exists for this API"
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

    routes = agw.get_routes(ApiId=api_id).get("Items", [])
    dups = [r for r in routes if r["RouteKey"] == "GET /dup"]
    assert len(dups) == 1, f"expected exactly one 'GET /dup' route, got {len(dups)}: {routes}"
    assert dups[0]["RouteId"] == original_id, (
        f"the rejected CreateRoute must not replace the original route "
        f"({dups[0]['RouteId']} != {original_id})"
    )

    other_id = agw.create_route(ApiId=api_id, RouteKey="POST /dup", Target=target)["RouteId"]
    assert other_id != original_id, "control: POST /dup must be a distinct route"
    keys = sorted(r["RouteKey"] for r in agw.get_routes(ApiId=api_id).get("Items", []))
    assert keys == ["GET /dup", "POST /dup"], (
        f"control: route keys are method-scoped so both must coexist, got {keys}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
