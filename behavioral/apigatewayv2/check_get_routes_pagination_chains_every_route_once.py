"""get-routes-pagination-chains-every-route-once."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-routes-pagination-chains-every-route-once"
GROUP = 'routing'
SERVICES = ['apigatewayv2']

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}

_ROUTE_KEYS = ["GET /a", "GET /b", "POST /c", "PUT /d/{id}", "DELETE /e", "$default", "ANY /f"]


def _error(fn):
    """(code, message) of the ClientError fn() raised. An unexpected success RAISES."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:happy-path", "cap:c2", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetRoutes (MaxResults=2, seven routes) and GetIntegrations (MaxResults=1) chains visit every
    item exactly once in bounded pages and then stop; a never-issued NextToken is refused.
    """
    agw = ctx.client("apigatewayv2")
    api_id = agw.create_api(
        Name=ctx.unique_name("sim2real-behav-httpapi-"), ProtocolType="HTTP", Tags=TAGS
    )["ApiId"]
    ctx.on_cleanup(lambda: agw.delete_api(ApiId=api_id))
    integ_ids = []
    for i in range(3):
        integ_ids.append(agw.create_integration(
            ApiId=api_id,
            IntegrationType="HTTP_PROXY",
            IntegrationUri=f"https://example.com/i{i}",
            IntegrationMethod="ANY",
            PayloadFormatVersion="1.0",
        )["IntegrationId"])
    route_ids = []
    for rk in _ROUTE_KEYS:
        route_ids.append(agw.create_route(
            ApiId=api_id, RouteKey=rk, Target=f"integrations/{integ_ids[0]}"
        )["RouteId"])

    def _chain(op, page_size):
        seen, sizes, token = [], [], None
        for _ in range(20):
            kw = {"ApiId": api_id, "MaxResults": str(page_size)}
            if token:
                kw["NextToken"] = token
            page = op(**kw)
            items = page.get("Items", [])
            sizes.append(len(items))
            seen.extend(items)
            token = page.get("NextToken")
            if not token:
                return seen, sizes
        raise AssertionError(f"pagination did not terminate within 20 pages; page sizes {sizes}")

    routes, sizes = _chain(agw.get_routes, 2)
    ids = [r["RouteId"] for r in routes]
    assert all(s <= 2 for s in sizes), f"GetRoutes MaxResults=2 returned page sizes {sizes}"
    assert len(ids) == len(set(ids)), f"a route appeared on more than one page; page sizes {sizes}"
    assert set(ids) == set(route_ids), (
        f"the GetRoutes chain must visit exactly the {len(route_ids)} created routes; got "
        f"{len(set(ids))} distinct, {len(set(route_ids) - set(ids))} missing"
    )
    keys = sorted(r["RouteKey"] for r in routes)
    assert keys == sorted(_ROUTE_KEYS), f"route keys across pages: {keys}"

    integs, sizes = _chain(agw.get_integrations, 1)
    iids = [i["IntegrationId"] for i in integs]
    assert all(s <= 1 for s in sizes), f"GetIntegrations MaxResults=1 returned page sizes {sizes}"
    assert sorted(iids) == sorted(integ_ids), (
        f"the GetIntegrations chain must visit each of the 3 integrations once; got {len(iids)} "
        f"items, {len(set(iids))} distinct"
    )

    code, message = _error(
        lambda: agw.get_routes(ApiId=api_id, MaxResults="2", NextToken="sim2real-not-a-token")
    )
    assert code == "BadRequestException", (
        f"an unissued NextToken: expected BadRequestException, got {code}: {message!r}"
    )
    expected = "Invalid position parameter"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
