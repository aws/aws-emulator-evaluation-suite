"""get-api-after-delete-rejected."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "get-api-after-delete-rejected"
GROUP = "state-machine"
SERVICES = ["appsync"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetApi on a deleted Api id returns NotFoundException, never stale/success data,
    and a subsequent mutation on the same dead id is refused the same specific way."""
    appsync = ctx.client("appsync")
    name = ctx.unique_name("sim2real-appsync-gone-")
    event_config = _event_config("API_KEY")

    created = appsync.create_api(
        name=name,
        eventConfig=event_config,
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )
    api_id = created["api"]["apiId"]
    ctx.on_cleanup(lambda: _delete_api_quiet(appsync, api_id))

    # Sanity: the Api is really there before we delete it.
    appsync.get_api(apiId=api_id)

    appsync.delete_api(apiId=api_id)

    try:
        resp = appsync.get_api(apiId=api_id)
    except Exception as exc:  # noqa: BLE001
        code, message = _error_from_exc(exc)
        assert code == "NotFoundException", f"expected NotFoundException, got {code!r}"
        assert message == "API not found.", f"unexpected GetApi message: {message!r}"
    else:
        raise AssertionError(
            f"GetApi succeeded on a deleted apiId and returned stale data: {resp!r}"
        )

    # A mutation on the same dead id must fail the same specific way, not silently
    # resurrect the Api or no-op against something that no longer exists.
    try:
        resp = appsync.update_api(apiId=api_id, name=name, eventConfig=event_config)
    except Exception as exc:  # noqa: BLE001
        code, message = _error_from_exc(exc)
        assert code == "NotFoundException", (
            f"expected NotFoundException on UpdateApi against a deleted apiId, got {code!r}"
        )
        assert message == "API not found.", f"unexpected UpdateApi message: {message!r}"
    else:
        raise AssertionError(
            f"UpdateApi succeeded on a deleted apiId and returned: {resp!r}"
        )


def _event_config(auth_type: str) -> dict[str, Any]:
    mode = {"authType": auth_type}
    return {
        "authProviders": [mode],
        "connectionAuthModes": [mode],
        "defaultPublishAuthModes": [mode],
        "defaultSubscribeAuthModes": [mode],
    }


def _error_from_exc(exc: Exception) -> tuple[str | None, str | None]:
    resp = getattr(exc, "response", None)
    if isinstance(resp, dict):
        err = resp.get("Error", {})
        return err.get("Code"), err.get("Message")
    return None, None


def _delete_api_quiet(appsync: Any, api_id: str) -> None:
    try:
        appsync.delete_api(apiId=api_id)
    except Exception as exc:  # noqa: BLE001
        if _error_from_exc(exc)[0] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
