"""api-lifecycle-state-transitions."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "api-lifecycle-state-transitions"
GROUP = "state-machine"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateApi->GetApi(active)->UpdateApi(persists)->DeleteApi->GetApi fails->UpdateApi fails."""
    appsync = ctx.client("appsync")
    name = ctx.unique_name("sim2real-appsync-api-")
    event_config = _event_config("API_KEY")

    created = appsync.create_api(
        name=name,
        eventConfig=event_config,
        ownerContact="initial-contact",
        tags={"sim2real-check": CHECK},
    )
    api_id = created["api"]["apiId"]
    assert created["api"]["name"] == name, (
        f"expected CreateApi to echo name={name!r}, got {created['api']['name']!r}"
    )
    ctx.on_cleanup(lambda: _delete_api_quiet(appsync, api_id))

    got = appsync.get_api(apiId=api_id)["api"]
    assert got["apiId"] == api_id, f"expected GetApi apiId={api_id!r}, got {got['apiId']!r}"
    assert got["name"] == name, f"expected GetApi name={name!r}, got {got['name']!r}"
    assert got["ownerContact"] == "initial-contact", (
        f"expected ownerContact='initial-contact', got {got['ownerContact']!r}"
    )
    assert got.get("dns"), "expected the active Api to expose dns endpoints"

    appsync.update_api(
        apiId=api_id, name=name, eventConfig=event_config, ownerContact="updated-contact"
    )
    got_after_update = appsync.get_api(apiId=api_id)["api"]
    assert got_after_update["ownerContact"] == "updated-contact", "UpdateApi change did not persist"
    assert got_after_update["apiId"] == api_id, "apiId must remain immutable across an update"

    appsync.delete_api(apiId=api_id)

    code, message = _error(lambda: appsync.get_api(apiId=api_id))
    assert code == "NotFoundException", (
        f"expected NotFoundException after DeleteApi, got {code!r} (or no error / stale data)"
    )
    assert message == "API not found.", f"expected AWS's exact not-found message, got {message!r}"

    mutate_code, mutate_message = _error(
        lambda: appsync.update_api(apiId=api_id, name=name, eventConfig=event_config)
    )
    assert mutate_code == "NotFoundException", (
        f"expected UpdateApi on a deleted apiId to fail NotFoundException, got {mutate_code!r}"
    )
    assert mutate_message == "API not found.", (
        f"expected AWS's exact not-found message from UpdateApi, got {mutate_message!r}"
    )


def _event_config(auth_type: str) -> dict[str, Any]:
    mode = {"authType": auth_type}
    return {
        "authProviders": [mode],
        "connectionAuthModes": [mode],
        "defaultPublishAuthModes": [mode],
        "defaultSubscribeAuthModes": [mode],
    }


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises,
    because a target that accepts a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _error_code_from_exc(exc: Exception) -> str | None:
    resp = getattr(exc, "response", None)
    if isinstance(resp, dict):
        return resp.get("Error", {}).get("Code")
    return None


def _delete_api_quiet(appsync: Any, api_id: str) -> None:
    try:
        appsync.delete_api(apiId=api_id)
    except Exception as exc:  # noqa: BLE001
        if _error_code_from_exc(exc) != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
