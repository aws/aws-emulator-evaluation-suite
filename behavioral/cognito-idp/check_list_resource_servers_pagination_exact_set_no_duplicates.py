"""list-resource-servers-pagination-exact-set-no-duplicates."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-resource-servers-pagination-exact-set-no-duplicates"
GROUP = "resource-server"
SERVICES = ["cognito-idp"]

_COUNT = 5
_PAGE_SIZE = 2


def _collect(idp, pool_id: str, page_size: int) -> list:
    identifiers, next_token = [], None
    while True:
        kwargs = {"UserPoolId": pool_id, "MaxResults": page_size}
        if next_token:
            kwargs["NextToken"] = next_token
        resp = idp.list_resource_servers(**kwargs)
        page = resp["ResourceServers"]
        assert len(page) <= page_size, f"page held {len(page)} servers, more than MaxResults={page_size}"
        identifiers.extend(s["Identifier"] for s in page)
        next_token = resp.get("NextToken")
        if not next_token:
            return identifiers


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListResourceServers paginated with MaxResults smaller than the pool's resource server
    count returns every created resource server exactly once, across however many pages NextToken
    requires.
    """
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-rspage-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    created = []
    for i in range(_COUNT):
        identifier = ctx.unique_name(f"sim2real-behav-rspage-api{i}-")
        idp.create_resource_server(
            UserPoolId=pool_id, Identifier=identifier, Name=identifier
        )
        created.append(identifier)

    paginated = _collect(idp, pool_id, _PAGE_SIZE)
    assert len(paginated) == len(set(paginated)), (
        f"ListResourceServers pagination returned a duplicate identifier: {paginated!r}"
    )
    assert set(paginated) == set(created), (
        f"expected exactly the {_COUNT} created resource servers, got {sorted(paginated)!r} "
        f"vs created {sorted(created)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
