"""get-api-not-found-after-delete."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-api-not-found-after-delete"
GROUP = "error-semantics"
SERVICES = ["appsync"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetApi on a deleted Api id returns NotFoundException, never stale data, and
    the dead id also rejects a mutation (UpdateApi) rather than silently recreating it."""
    appsync = ctx.client("appsync")
    name = ctx.unique_name("sim2real-behav-")
    event_config = _event_config()

    api = appsync.create_api(
        name=name, eventConfig=event_config, tags={"sim2real": "behavioral"}
    )["api"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: _delete_api_quiet(appsync, api_id))

    # Sanity: the API is live and GetApi reflects it.
    got = appsync.get_api(apiId=api_id)["api"]
    assert got["apiId"] == api_id
    assert got["name"] == name

    appsync.delete_api(apiId=api_id)

    # GetApi must never return stale data for a deleted (or deleting) resource -- it must
    # reject with NotFoundException.
    code, message = _error(lambda: appsync.get_api(apiId=api_id))
    assert code == "NotFoundException", f"expected NotFoundException, got {code!r}"
    assert message == "API not found.", f"unexpected GetApi message: {message!r}"

    # The dead id must also reject a mutation, not just a read -- otherwise a target
    # that lazily recreates the resource on write would pass the read-only check above.
    update_code, update_message = _error(
        lambda: appsync.update_api(apiId=api_id, name=name, eventConfig=event_config)
    )
    assert update_code == "NotFoundException", (
        f"expected UpdateApi on the deleted apiId to fail with NotFoundException, "
        f"got {update_code!r}"
    )
    assert update_message == "API not found.", f"unexpected UpdateApi message: {update_message!r}"


def _event_config() -> dict:
    return {
        "authProviders": [{"authType": "API_KEY"}],
        "connectionAuthModes": [{"authType": "API_KEY"}],
        "defaultPublishAuthModes": [{"authType": "API_KEY"}],
        "defaultSubscribeAuthModes": [{"authType": "API_KEY"}],
    }


def _error(fn):
    """Call fn() and return its botocore error (code, message); a call that succeeds raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"expected the call to be rejected, but it succeeded and returned {result!r}"
    )


def _delete_api_quiet(appsync, api_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        appsync.delete_api(apiId=api_id)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
