"""create-channel-namespace-duplicate-conflict-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-channel-namespace-duplicate-conflict-rejected"
GROUP = "error-semantics"
SERVICES = ["appsync"]

_EVENT_CONFIG = {
    "authProviders": [{"authType": "API_KEY"}],
    "connectionAuthModes": [{"authType": "API_KEY"}],
    "defaultPublishAuthModes": [{"authType": "API_KEY"}],
    "defaultSubscribeAuthModes": [{"authType": "API_KEY"}],
}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateChannelNamespace is rejected with ConflictException for a name already in use on the
    Api. Deleting the conflicting namespace and retrying the identical call then succeeds, which
    is what ties the ConflictException to the name collision rather than a blanket rejection."""
    appsync = ctx.client("appsync")
    api_id = _create_event_api(ctx)
    ns_name = ctx.unique_name("sim2real-ns-")

    appsync.create_channel_namespace(apiId=api_id, name=ns_name, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: appsync.delete_channel_namespace(apiId=api_id, name=ns_name))

    # Boundary: same name, same Api -> conflict, not silently accepted/overwritten.
    code, message = _error(lambda: appsync.create_channel_namespace(apiId=api_id, name=ns_name))
    assert code == "ConflictException", f"expected ConflictException, got {code}"
    assert message == "Channel namespace already exists.", f"expected the exact conflict message, got {message!r}"

    # Confirm exactly one namespace with this name exists (no accidental duplicate/overwrite).
    resp = appsync.list_channel_namespaces(apiId=api_id)
    matches = [n for n in resp["channelNamespaces"] if n["name"] == ns_name]
    assert len(matches) == 1, f"expected exactly one namespace named {ns_name}, got {matches}"

    # Restore: remove the conflicting namespace, then the identical call must now succeed --
    # proving the ConflictException tracked the name collision, not a standing rejection of the name.
    appsync.delete_channel_namespace(apiId=api_id, name=ns_name)
    recreated = appsync.create_channel_namespace(
        apiId=api_id, name=ns_name, tags={"sim2real": CHECK}
    )["channelNamespace"]
    assert recreated["name"] == ns_name, f"expected recreate to succeed with {ns_name}, got {recreated}"


def _create_event_api(ctx) -> str:
    appsync = ctx.client("appsync")
    name = ctx.unique_name("sim2real-behav-")
    resp = appsync.create_api(name=name, eventConfig=_EVENT_CONFIG, tags={"sim2real": CHECK})
    api_id = resp["api"]["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_api(apiId=api_id))
    return api_id


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected success
    raises, so an emulator that accepts what AWS refuses fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
