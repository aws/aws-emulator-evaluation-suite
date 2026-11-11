"""api-resource-lifecycle-state-transitions."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "api-resource-lifecycle-state-transitions"
GROUP = "state-machine"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateApi produces an active Event API visible via GetApi/ListApis, UpdateApi persists
    mutations to name/eventConfig, and DeleteApi removes it such that GetApi 404s."""
    appsync = ctx.client("appsync")
    name = ctx.unique_name("sim2real-behav-")

    event_config = {
        "authProviders": [{"authType": "API_KEY"}],
        "connectionAuthModes": [{"authType": "API_KEY"}],
        "defaultPublishAuthModes": [{"authType": "API_KEY"}],
        "defaultSubscribeAuthModes": [{"authType": "API_KEY"}],
    }

    created = appsync.create_api(
        name=name,
        eventConfig=event_config,
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["api"]
    api_id = created["apiId"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: appsync.delete_api(apiId=api_id)))

    assert created["name"] == name, f"expected created name {name!r}, got {created['name']!r}"
    assert created["apiArn"], "expected CreateApi to return a populated apiArn"
    assert created["dns"], "expected dns endpoints on a newly created Event Api"
    assert created["eventConfig"]["authProviders"][0]["authType"] == "API_KEY", (
        f"expected authProviders[0].authType API_KEY, got "
        f"{created['eventConfig']['authProviders'][0].get('authType')!r}"
    )

    fetched = appsync.get_api(apiId=api_id)["api"]
    assert fetched["apiId"] == api_id, f"expected apiId {api_id!r}, got {fetched['apiId']!r}"
    assert fetched["name"] == name, f"expected name {name!r}, got {fetched['name']!r}"
    assert fetched["apiArn"] == created["apiArn"], (
        f"expected apiArn to remain {created['apiArn']!r}, got {fetched['apiArn']!r}"
    )

    found = False
    token = None
    for _ in range(30):
        kwargs = {"maxResults": 25}
        if token:
            kwargs["nextToken"] = token
        page = appsync.list_apis(**kwargs)
        if any(a["apiId"] == api_id for a in page.get("apis", [])):
            found = True
            break
        token = page.get("nextToken")
        if not token:
            break
    assert found, f"created Api {api_id} not visible via ListApis"

    new_name = f"{name}-renamed"
    updated_event_config = dict(event_config)
    updated = appsync.update_api(apiId=api_id, name=new_name, eventConfig=updated_event_config)["api"]
    assert updated["apiId"] == api_id, f"expected apiId {api_id!r} unchanged by UpdateApi, got {updated['apiId']!r}"
    assert updated["name"] == new_name, f"expected updated name {new_name!r}, got {updated['name']!r}"

    refetched = appsync.get_api(apiId=api_id)["api"]
    assert refetched["name"] == new_name, (
        f"UpdateApi did not persist the new name: expected {new_name!r}, got {refetched['name']!r}"
    )

    appsync.delete_api(apiId=api_id)

    code_after_delete, message_after_delete = _error(lambda: appsync.get_api(apiId=api_id))
    assert code_after_delete == "NotFoundException", (
        f"expected NotFoundException from GetApi after DeleteApi, got {code_after_delete!r}"
    )
    assert message_after_delete == "API not found.", (
        f"expected AWS's exact not-found message from GetApi, got {message_after_delete!r}"
    )

    mutation_code_after_delete, mutation_message_after_delete = _error(
        lambda: appsync.update_api(apiId=api_id, name=new_name, eventConfig=updated_event_config)
    )
    assert mutation_code_after_delete == "NotFoundException", (
        f"expected UpdateApi on a deleted apiId to fail with NotFoundException, "
        f"got {mutation_code_after_delete!r}"
    )
    assert mutation_message_after_delete == "API not found.", (
        f"expected AWS's exact not-found message from UpdateApi, got {mutation_message_after_delete!r}"
    )

    ids_after_delete = {a["apiId"] for page in _list_all_apis(appsync) for a in page}
    assert api_id not in ids_after_delete, f"deleted Api {api_id} still visible via ListApis"


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises,
    because a target that accepts a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _ignore_not_found(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] != "NotFoundException":
            raise


def _list_all_apis(appsync):
    token = None
    while True:
        kwargs = {"maxResults": 25}
        if token:
            kwargs["nextToken"] = token
        page = appsync.list_apis(**kwargs)
        yield page.get("apis", [])
        token = page.get("nextToken")
        if not token:
            break


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
