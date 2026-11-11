"""websocket-api-create-route-delete."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}

CHECK = "websocket-api-create-route-delete"
GROUP = 'websocket'
SERVICES = ['apigatewayv2']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateApi(WEBSOCKET) + $connect route; GetRoute reflects it; DeleteRoute makes it
    unreadable, unlisted and unmutable; the deleted API is then unreadable, unlisted and unmutable."""
    agw = ctx.client("apigatewayv2")
    created = agw.create_api(Name=ctx.unique_name("sim2real-behav-wsapi-"), ProtocolType="WEBSOCKET", Tags=TAGS, RouteSelectionExpression="$request.body.action")
    ctx.on_cleanup(lambda: _delete_api_if_present(agw, created["ApiId"]))
    api_id = created["ApiId"]
    assert created["ProtocolType"] == "WEBSOCKET", (
        f"expected WEBSOCKET, got {created.get('ProtocolType')}"
    )
    assert created.get("RouteSelectionExpression") == "$request.body.action", (
        f"route selection expression mismatch: {created.get('RouteSelectionExpression')}"
    )
    got_api = agw.get_api(ApiId=api_id)
    assert got_api.get("RouteSelectionExpression") == "$request.body.action", (
        f"GetApi lost RouteSelectionExpression: {got_api.get('RouteSelectionExpression')}"
    )

    route = agw.create_route(ApiId=api_id, RouteKey="$connect")
    route_id = route["RouteId"]

    got = agw.get_route(ApiId=api_id, RouteId=route_id)
    assert got["RouteKey"] == "$connect", f"route key mismatch: {got.get('RouteKey')}"

    agw.delete_route(ApiId=api_id, RouteId=route_id)
    # Beat 1: the by-id read is NotFoundException 404 (AWS's message names no id).
    _assert_not_found(
        _client_error(lambda: agw.get_route(ApiId=api_id, RouteId=route_id)), "GetRoute on the deleted route",
        expected_message="Invalid route identifier specified",
    )
    # Beat 2: the route is absent from the API's route listing.
    route_ids = [r.get("RouteId") for r in _all_routes(agw, api_id)]
    assert route_id not in route_ids, f"deleted route still listed by GetRoutes: {route_ids!r}"
    # Beat 3: a mutation on the dead route is refused.
    _assert_not_found(
        _client_error(lambda: agw.update_route(ApiId=api_id, RouteId=route_id, RouteKey="$disconnect")),
        "UpdateRoute on the deleted route",
        expected_message="Invalid route identifier specified",
    )

    agw.delete_api(ApiId=api_id)
    # Beat 1: the API read is NotFoundException 404.
    _assert_not_found(_client_error(lambda: agw.get_api(ApiId=api_id)), "GetApi on the deleted API", expected_message=f"Invalid API identifier specified {ctx.account}:{api_id}")
    # Beat 2: the API is absent from the GetApis listing.
    api_ids = [a.get("ApiId") for a in _all_apis(agw)]
    assert api_id not in api_ids, f"deleted API {api_id} still listed by GetApis"
    # Beat 3: a mutation on the dead API is refused.
    _assert_not_found(
        _client_error(lambda: agw.update_api(ApiId=api_id, Description="post-delete")),
        "UpdateApi on the deleted API",
        expected_message=f"Invalid API identifier specified {ctx.account}:{api_id}",
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return dict(exc.response.get("Error", {}), HTTPStatusCode=status)
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _assert_not_found(err, what, expected_message):
    """err is NotFoundException with HTTP 404 and the exact message."""
    assert err.get("Code") == "NotFoundException", f"{what}: expected NotFoundException, got {err.get('Code')!r}"
    assert err.get("HTTPStatusCode") == 404, f"{what}: expected HTTP 404, got {err.get('HTTPStatusCode')!r}"
    assert err.get("Message") == expected_message, f'expected the message {expected_message!r}, got {err.get("Message")!r}'


def _all_routes(agw, api_id):
    """Every route GetRoutes returns for the API, following NextToken."""
    items, token = [], None
    while True:
        page = agw.get_routes(ApiId=api_id, **({"NextToken": token} if token else {}))
        items += page.get("Items", [])
        token = page.get("NextToken")
        if not token:
            return items


def _all_apis(agw):
    """Every API GetApis returns, following NextToken."""
    items, token = [], None
    while True:
        page = agw.get_apis(**({"NextToken": token} if token else {}))
        items += page.get("Items", [])
        token = page.get("NextToken")
        if not token:
            return items


def _delete_api_if_present(agw, api_id):
    """Teardown: the check deletes the API itself on success."""
    try:
        agw.delete_api(ApiId=api_id)
    except agw.exceptions.NotFoundException:
        pass


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
