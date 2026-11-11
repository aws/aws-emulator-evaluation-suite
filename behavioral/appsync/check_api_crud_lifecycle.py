"""api-crud-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "api-crud-lifecycle"
GROUP = "state-machine"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateApi->GetApi->UpdateApi(name/config persists)->ListApis(contains it)->DeleteApi."""
    appsync = ctx.client("appsync")

    name = ctx.unique_name("sim2real-appsync-api-")
    event_config = {
        "authProviders": [{"authType": "API_KEY"}],
        "connectionAuthModes": [{"authType": "API_KEY"}],
        "defaultPublishAuthModes": [{"authType": "API_KEY"}],
        "defaultSubscribeAuthModes": [{"authType": "API_KEY"}],
    }

    created = appsync.create_api(
        name=name,
        eventConfig=event_config,
        ownerContact="team-a",
        tags={"sim2real-check": CHECK},
    )["api"]
    api_id = created["apiId"]

    def _cleanup():
        try:
            appsync.delete_api(apiId=api_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    assert created["name"] == name, f"expected name {name!r}, got {created['name']!r}"
    assert created["ownerContact"] == "team-a", (
        f"expected ownerContact 'team-a', got {created['ownerContact']!r}"
    )
    assert created["eventConfig"]["connectionAuthModes"] == [{"authType": "API_KEY"}], (
        f"connectionAuthModes did not echo the request: {created['eventConfig']!r}"
    )
    assert created["apiArn"], "apiArn should be populated"

    fetched = appsync.get_api(apiId=api_id)["api"]
    assert fetched["apiId"] == api_id, f"expected apiId {api_id!r}, got {fetched['apiId']!r}"
    assert fetched["name"] == name, f"expected name {name!r}, got {fetched['name']!r}"
    assert fetched["ownerContact"] == "team-a", (
        f"expected ownerContact 'team-a', got {fetched['ownerContact']!r}"
    )

    updated_name = f"{name}-v2"
    updated = appsync.update_api(
        apiId=api_id, name=updated_name, eventConfig=event_config, ownerContact="team-b"
    )["api"]
    assert updated["name"] == updated_name, (
        f"expected name {updated_name!r}, got {updated['name']!r}"
    )
    assert updated["ownerContact"] == "team-b", (
        f"expected ownerContact 'team-b', got {updated['ownerContact']!r}"
    )
    assert updated["apiId"] == api_id, (
        f"apiId must remain immutable across UpdateApi: expected {api_id!r}, got {updated['apiId']!r}"
    )

    fetched_after_update = appsync.get_api(apiId=api_id)["api"]
    assert fetched_after_update["name"] == updated_name, (
        f"UpdateApi name did not persist: expected {updated_name!r}, "
        f"got {fetched_after_update['name']!r}"
    )
    assert fetched_after_update["ownerContact"] == "team-b", (
        f"UpdateApi ownerContact did not persist: expected 'team-b', "
        f"got {fetched_after_update['ownerContact']!r}"
    )

    found = None
    paginator = appsync.get_paginator("list_apis")
    for page in paginator.paginate():
        for api in page.get("apis", []):
            if api["apiId"] == api_id:
                found = api
                break
        if found:
            break
    assert found is not None, "api not present in ListApis"
    assert found["name"] == updated_name, (
        f"ListApis returned stale name: expected {updated_name!r}, got {found['name']!r}"
    )

    appsync.delete_api(apiId=api_id)

    try:
        appsync.get_api(apiId=api_id)
        raise AssertionError("expected NotFoundException from GetApi after DeleteApi")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "NotFoundException", (
            f"expected NotFoundException from GetApi after DeleteApi, got {code!r}"
        )
        message = exc.response["Error"].get("Message")
        assert message == "API not found.", message

    try:
        appsync.update_api(
            apiId=api_id, name=f"{updated_name}-dead", eventConfig=event_config
        )
        raise AssertionError("expected NotFoundException from UpdateApi on a deleted apiId")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "NotFoundException", (
            f"expected NotFoundException from UpdateApi on a deleted apiId, got {code!r}"
        )
        message = exc.response["Error"].get("Message")
        assert message == "API not found.", message


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
