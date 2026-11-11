"""op-contract-get-channel-namespace."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-get-channel-namespace"
GROUP = "error-semantics"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetChannelNamespace returns the persisted auth-mode config and 404s for an unknown namespace."""
    appsync = ctx.client("appsync")
    api_id = _create_event_api(ctx)
    name = ctx.unique_name("sim2real-ns-")

    created = appsync.create_channel_namespace(
        apiId=api_id,
        name=name,
        subscribeAuthModes=[{"authType": "API_KEY"}],
        publishAuthModes=[{"authType": "API_KEY"}],
        tags={"sim2real-check": CHECK},
    )["channelNamespace"]
    ctx.on_cleanup(lambda: appsync.delete_channel_namespace(apiId=api_id, name=name))

    fetched = appsync.get_channel_namespace(apiId=api_id, name=name)["channelNamespace"]
    assert fetched["name"] == name, f"expected name {name!r}, got {fetched['name']!r}"
    assert fetched["apiId"] == api_id, f"expected apiId {api_id!r}, got {fetched['apiId']!r}"
    assert fetched["channelNamespaceArn"] == created["channelNamespaceArn"], (
        f"expected ARN {created['channelNamespaceArn']!r}, got {fetched['channelNamespaceArn']!r}"
    )
    assert fetched["subscribeAuthModes"] == [{"authType": "API_KEY"}], (
        f"expected subscribeAuthModes [{{'authType': 'API_KEY'}}], got {fetched['subscribeAuthModes']!r}"
    )
    assert fetched["publishAuthModes"] == [{"authType": "API_KEY"}], (
        f"expected publishAuthModes [{{'authType': 'API_KEY'}}], got {fetched['publishAuthModes']!r}"
    )
    assert fetched["created"] == created["created"], (
        f"expected created {created['created']!r}, got {fetched['created']!r}"
    )

    # Error boundary: a namespace name that was never created -> NotFoundException.
    code, code_msg = _error(
        lambda: appsync.get_channel_namespace(apiId=api_id, name="never-created-ns")
    )
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert code_msg == "Channel namespace not found.", f"unexpected message: {code_msg!r}"


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
        tags={"sim2real-check": CHECK},
    )
    api_id = resp["api"]["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_api(apiId=api_id))
    return api_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
