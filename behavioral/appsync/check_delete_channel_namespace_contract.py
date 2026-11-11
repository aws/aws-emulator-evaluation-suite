"""op-contract-delete-channel-namespace."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-delete-channel-namespace"
GROUP = "error-semantics"
SERVICES = ["appsync"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteChannelNamespace removes the namespace; GetChannelNamespace then 404s, and the
    freed name is reusable by a subsequent create."""
    appsync = ctx.client("appsync")
    api_id = _create_event_api(ctx)
    name = ctx.unique_name("sim2real-ns-")
    appsync.create_channel_namespace(apiId=api_id, name=name)

    appsync.delete_channel_namespace(apiId=api_id, name=name)

    code, code_msg = _error(lambda: appsync.get_channel_namespace(apiId=api_id, name=name))
    assert code == "NotFoundException", (
        f"expected NotFoundException after delete, got {code}"
    )
    assert code_msg == "Channel namespace not found.", f"unexpected message: {code_msg!r}"

    # Error boundary: deleting the already-deleted namespace again -> NotFoundException.
    code, code_msg = _error(
        lambda: appsync.delete_channel_namespace(apiId=api_id, name=name)
    )
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert code_msg == "", f"unexpected message: {code_msg!r}"

    # The identifier is reusable: a fresh create with the same name now succeeds.
    appsync.create_channel_namespace(apiId=api_id, name=name)
    recreated = appsync.get_channel_namespace(apiId=api_id, name=name)["channelNamespace"]
    assert recreated["name"] == name, (
        f"expected the freed name to be reusable, got {recreated.get('name')!r}"
    )
    appsync.delete_channel_namespace(apiId=api_id, name=name)


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED: {result!r}")


def _create_event_api(ctx) -> str:
    appsync = ctx.client("appsync")
    event_config = {
        "authProviders": [{"authType": "API_KEY"}],
        "connectionAuthModes": [{"authType": "API_KEY"}],
        "defaultPublishAuthModes": [{"authType": "API_KEY"}],
        "defaultSubscribeAuthModes": [{"authType": "API_KEY"}],
    }
    resp = appsync.create_api(
        name=ctx.unique_name("sim2real-behav-evtapi-"),
        eventConfig=event_config,
        tags={"sim2real": "delete-channel-namespace-contract"},
    )
    api_id = resp["api"]["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_api(apiId=api_id))
    return api_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
