"""op-contract-create-channel-namespace."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-create-channel-namespace"
GROUP = "error-semantics"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateChannelNamespace persists auth modes, rejects a duplicate name while the
    original stands, and accepts the identical call again once the conflicting namespace
    is gone."""
    appsync = ctx.client("appsync")
    api_id = _create_event_api(ctx)
    name = ctx.unique_name("sim2real-ns-")
    auth_modes = [{"authType": "API_KEY"}]

    resp = appsync.create_channel_namespace(
        apiId=api_id,
        name=name,
        subscribeAuthModes=auth_modes,
        publishAuthModes=auth_modes,
    )
    ns = resp["channelNamespace"]
    ctx.on_cleanup(lambda: appsync.delete_channel_namespace(apiId=api_id, name=name))

    assert ns["name"] == name
    assert ns["apiId"] == api_id
    assert ns["channelNamespaceArn"], "channelNamespaceArn missing"
    assert ns["subscribeAuthModes"] == auth_modes
    assert ns["publishAuthModes"] == auth_modes

    fetched = appsync.get_channel_namespace(apiId=api_id, name=name)["channelNamespace"]
    assert fetched["channelNamespaceArn"] == ns["channelNamespaceArn"]

    # Break: duplicate namespace name on the same API -> ConflictException.
    code, code_msg = _error(
        lambda: appsync.create_channel_namespace(apiId=api_id, name=name)
    )
    assert code == "ConflictException", f"expected ConflictException, got {code}"
    assert code_msg == "Channel namespace already exists.", f"unexpected message: {code_msg!r}"

    # Effect absent: the rejected duplicate left exactly the original namespace in place.
    listed = appsync.list_channel_namespaces(apiId=api_id)["channelNamespaces"]
    matches = [n for n in listed if n["name"] == name]
    assert len(matches) == 1, f"expected exactly one namespace named {name!r}, got {matches}"
    assert matches[0]["channelNamespaceArn"] == ns["channelNamespaceArn"]

    # Restore: remove the namespace that was the source of the conflict, then the
    # identical create call must now succeed -- proving the boundary is the existing
    # name, not a blanket rejection.
    appsync.delete_channel_namespace(apiId=api_id, name=name)
    _wait_until_gone(appsync, api_id, name)

    recreated = appsync.create_channel_namespace(
        apiId=api_id,
        name=name,
        subscribeAuthModes=auth_modes,
        publishAuthModes=auth_modes,
    )["channelNamespace"]
    assert recreated["name"] == name
    assert recreated["channelNamespaceArn"], "channelNamespaceArn missing on recreate"

    # Terminal read: independent of the mutating call, at the destination.
    refetched = appsync.get_channel_namespace(apiId=api_id, name=name)["channelNamespace"]
    assert refetched["channelNamespaceArn"] == recreated["channelNamespaceArn"]
    assert refetched["subscribeAuthModes"] == auth_modes


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED: {result!r}")


def _wait_until_gone(appsync, api_id, name, *, timeout_s=30.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = "present"
    while time.monotonic() < deadline:
        try:
            appsync.get_channel_namespace(apiId=api_id, name=name)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "NotFoundException":
                return
            last = code
        time.sleep(interval_s)
    raise AssertionError(
        f"channel namespace {name!r} not gone within {timeout_s}s; last saw {last!r}"
    )


def _create_event_api(ctx) -> str:
    appsync = ctx.client("appsync")
    event_config = {
        "authProviders": [{"authType": "API_KEY"}],
        "connectionAuthModes": [{"authType": "API_KEY"}],
        "defaultPublishAuthModes": [{"authType": "API_KEY"}],
        "defaultSubscribeAuthModes": [{"authType": "API_KEY"}],
    }
    resp = appsync.create_api(
        name=ctx.unique_name("sim2real-behav-evtapi-"), eventConfig=event_config
    )
    api_id = resp["api"]["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_api(apiId=api_id))
    return api_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
