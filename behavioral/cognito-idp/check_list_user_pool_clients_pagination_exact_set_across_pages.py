"""list-user-pool-clients-pagination-exact-set-across-pages."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-user-pool-clients-pagination-exact-set-across-pages"
GROUP = "search-and-filtering"
SERVICES = ["cognito-idp"]

_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListUserPoolClients with MaxResults smaller than the client count pages through every
    client exactly once, and the final page carries no further continuation token."""
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-lupc-pool-"), UserPoolTags=_TAGS,
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    created = {}
    for i in range(3):
        name = ctx.unique_name(f"sim2real-behav-lupc-client-{i}-")
        client_id = idp.create_user_pool_client(UserPoolId=pool_id, ClientName=name)["UserPoolClient"]["ClientId"]
        created[client_id] = name

    pages = 0
    collected = {}
    token = None
    while True:
        kwargs = {"UserPoolId": pool_id, "MaxResults": 1}
        if token:
            kwargs["NextToken"] = token
        page = idp.list_user_pool_clients(**kwargs)
        page_clients = page["UserPoolClients"]
        assert len(page_clients) <= 1, f"MaxResults=1 but a page returned {len(page_clients)} clients"
        for c in page_clients:
            assert c["ClientId"] not in collected, f"client {c['ClientId']!r} returned on more than one page"
            collected[c["ClientId"]] = c["ClientName"]
        pages += 1
        token = page.get("NextToken")
        if not token:
            break
        assert pages <= len(created) + 1, f"still paginating after {pages} pages for {len(created)} clients"

    assert pages == len(created), f"expected {len(created)} pages of 1 client each, got {pages}"
    assert collected == created, f"expected {created!r} across every page, got {collected!r}"

    last = idp.list_user_pool_clients(UserPoolId=pool_id, MaxResults=60)
    assert "NextToken" not in last, f"a page sized above the client count still carried a NextToken: {last!r}"
    assert {c["ClientId"] for c in last["UserPoolClients"]} == set(created), (
        f"expected exactly the created clients in an unpaginated listing, got {last['UserPoolClients']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
