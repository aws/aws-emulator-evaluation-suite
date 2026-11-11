"""list-apis-pagination."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "list-apis-pagination"
GROUP = "ordering"
SERVICES = ["appsync"]

_COUNT = 4


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListApis paginates deterministically and relative ordering of tracked APIs is stable
    even when an unrelated Api is created between the two full traversals."""
    appsync = ctx.client("appsync")
    event_config = {
        "authProviders": [{"authType": "API_KEY"}],
        "connectionAuthModes": [{"authType": "API_KEY"}],
        "defaultPublishAuthModes": [{"authType": "API_KEY"}],
        "defaultSubscribeAuthModes": [{"authType": "API_KEY"}],
    }

    tracked_ids: list[str] = []
    for i in range(_COUNT):
        name = ctx.unique_name(f"sim2real-api{i}-")
        api = appsync.create_api(
            name=name, eventConfig=event_config, tags={"sim2real": "list-apis-pagination"}
        )["api"]
        api_id = api["apiId"]
        tracked_ids.append(api_id)
        ctx.on_cleanup(lambda a=api_id: appsync.delete_api(apiId=a))

    tracked_set = set(tracked_ids)

    pass1 = _list_all_api_ids(appsync, page_size=2)
    ours_1 = [a for a in pass1 if a in tracked_set]
    assert len(ours_1) == _COUNT, f"expected {_COUNT} tracked APIs in pass1, got {len(ours_1)}"

    # Create an unrelated API between the two full traversals to probe cursor stability.
    distractor_name = ctx.unique_name("sim2real-api-distractor-")
    distractor = appsync.create_api(
        name=distractor_name, eventConfig=event_config, tags={"sim2real": "list-apis-pagination"}
    )["api"]
    distractor_id = distractor["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_api(apiId=distractor_id))

    pass2 = _list_all_api_ids(appsync, page_size=2)
    ours_2 = [a for a in pass2 if a in tracked_set]
    assert len(ours_2) == _COUNT, f"expected {_COUNT} tracked APIs in pass2, got {len(ours_2)}"

    assert ours_1 == ours_2, (
        "ListApis relative order of pre-existing APIs changed after an unrelated API was "
        f"created between traversals: {ours_1!r} != {ours_2!r}"
    )
    assert len(pass1) == len(set(pass1)), "ListApis returned a duplicate apiId in one traversal"
    assert len(pass2) == len(set(pass2)), "ListApis returned a duplicate apiId in one traversal"
    assert distractor_id in pass2, "newly created API did not appear in a subsequent full ListApis traversal"


def _list_all_api_ids(appsync: Any, page_size: int) -> list[str]:
    ids: list[str] = []
    token = None
    while True:
        kwargs: dict[str, Any] = {"maxResults": page_size}
        if token:
            kwargs["nextToken"] = token
        resp = appsync.list_apis(**kwargs)
        ids.extend(a["apiId"] for a in resp.get("apis", []))
        token = resp.get("nextToken")
        if not token:
            break
    return ids


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
