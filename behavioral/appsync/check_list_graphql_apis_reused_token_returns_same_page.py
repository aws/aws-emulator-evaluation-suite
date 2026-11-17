"""list-graphql-apis-reused-token-returns-same-page."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-graphql-apis-reused-token-returns-same-page"
GROUP = 'graphql-api'
SERVICES = ['appsync']

_PAGE_SIZE = 2
_API_COUNT = 3


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListGraphqlApis packs every non-terminal page to maxResults, the terminal page of a
    full walk carries no nextToken, and handing an already-used nextToken back again returns
    the same page of apis rather than advancing or erroring.
    """
    svc = ctx.client("appsync")
    own_ids = set()
    for _ in range(_API_COUNT):
        api = svc.create_graphql_api(
            name=ctx.unique_name("sim2real-behav-appsync-list-"),
            authenticationType="API_KEY",
            tags={"sim2real": CHECK},
        )["graphqlApi"]
        own_ids.add(api["apiId"])
        ctx.on_cleanup(lambda _id=api["apiId"]: svc.delete_graphql_api(apiId=_id))

    pages = _walk_until_complete(svc, own_ids, deadline=time.monotonic() + 30.0)

    assert len(pages) >= 2, (
        f"expected at least 2 pages for {_API_COUNT} apis at maxResults={_PAGE_SIZE}, got {pages}"
    )
    for page in pages[:-1]:
        assert len(page["ids"]) == _PAGE_SIZE, (
            f"a non-terminal page held {len(page['ids'])} apis, expected exactly {_PAGE_SIZE}: {page}"
        )
    assert pages[-1]["next_token"] is None, (
        f"the walk's terminal page still carried a nextToken: {pages[-1]}"
    )

    seen = [api_id for page in pages for api_id in page["ids"]]
    for api_id in own_ids:
        assert seen.count(api_id) == 1, (
            f"api {api_id!r} appeared {seen.count(api_id)} time(s) across the walk, expected 1: {seen}"
        )

    reused_token = pages[0]["next_token"]
    replay = svc.list_graphql_apis(maxResults=_PAGE_SIZE, nextToken=reused_token)
    replay_ids = [a["apiId"] for a in replay["graphqlApis"]]
    assert replay_ids == pages[1]["ids"], (
        f"handing back the already-used token returned {replay_ids}, expected the same page "
        f"{pages[1]['ids']} it returned the first time"
    )
    assert replay.get("nextToken") == pages[1]["next_token"], (
        f"replaying the token changed the follow-on nextToken: first saw "
        f"{pages[1]['next_token']!r}, replay gave {replay.get('nextToken')!r}"
    )


def _walk_until_complete(svc, own_ids, *, deadline):
    """Page through ListGraphqlApis at maxResults until every id in own_ids was listed once.

    Retries the whole walk on a monotonic deadline: a just-created api can briefly miss a page
    boundary, which a single pass would misreport as missing rather than racing.
    """
    last_pages = []
    while True:
        pages = []
        token = None
        while True:
            kwargs = {"maxResults": _PAGE_SIZE}
            if token:
                kwargs["nextToken"] = token
            result = svc.list_graphql_apis(**kwargs)
            token = result.get("nextToken")
            pages.append({"ids": [a["apiId"] for a in result["graphqlApis"]], "next_token": token})
            if not token:
                break
        last_pages = pages
        found = {api_id for page in pages for api_id in page["ids"]} & own_ids
        if found == own_ids:
            return pages
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"a full pagination walk never surfaced every created api: missing "
                f"{own_ids - found}, last walk {pages}"
            )
        time.sleep(1.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
