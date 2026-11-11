"""op-contract-update-channel-namespace."""
from __future__ import annotations

CHECK = "op-contract-update-channel-namespace"
GROUP = "error-semantics"
SERVICES = ["appsync"]

from behavioral_harness import tags


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateChannelNamespace persists new codeHandlers, visible via GetChannelNamespace; NotFoundException on unknown namespace name."""
    appsync = ctx.client("appsync")
    event_config = {
        "authProviders": [{"authType": "API_KEY"}],
        "connectionAuthModes": [{"authType": "API_KEY"}],
        "defaultPublishAuthModes": [{"authType": "API_KEY"}],
        "defaultSubscribeAuthModes": [{"authType": "API_KEY"}],
    }
    api = appsync.create_api(
        name=ctx.unique_name("sim2real-behav-"), eventConfig=event_config
    )["api"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_api(apiId=api_id))

    ns_name = ctx.unique_name("ns-")
    appsync.create_channel_namespace(
        apiId=api_id,
        name=ns_name,
        publishAuthModes=[{"authType": "API_KEY"}],
        subscribeAuthModes=[{"authType": "API_KEY"}],
    )
    original = appsync.get_channel_namespace(apiId=api_id, name=ns_name)["channelNamespace"]
    assert original.get("codeHandlers") is None

    code_handlers = "export function onPublish(ctx) {\n  return ctx.events;\n}\n"
    updated = appsync.update_channel_namespace(
        apiId=api_id, name=ns_name, codeHandlers=code_handlers
    )["channelNamespace"]
    assert updated["codeHandlers"] == code_handlers

    fetched = appsync.get_channel_namespace(apiId=api_id, name=ns_name)["channelNamespace"]
    assert fetched["codeHandlers"] == code_handlers
    assert fetched["lastModified"] >= original["lastModified"]

    code, message = _error(
        lambda: appsync.update_channel_namespace(apiId=api_id, name="nonexistent-namespace-xyz")
    )
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    # AWS refuses an unknown namespace name with no message text
    assert message == "", message


def _error(fn):
    """Call fn(); return its error code. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected NotFoundException, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
