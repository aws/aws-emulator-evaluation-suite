"""op-contract-list-channel-namespaces."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-list-channel-namespaces"
GROUP = "error-semantics"
SERVICES = ["appsync"]

_BOGUS_API_ID = "sim2real-missing-api-id-0005"

_EVENT_CONFIG = {
    "authProviders": [{"authType": "API_KEY"}],
    "connectionAuthModes": [{"authType": "API_KEY"}],
    "defaultPublishAuthModes": [{"authType": "API_KEY"}],
    "defaultSubscribeAuthModes": [{"authType": "API_KEY"}],
}


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListChannelNamespaces surfaces a created namespace's name; unknown apiId 404s."""
    appsync = ctx.client("appsync")
    api_id = _create_event_api(ctx)
    ns_name = ctx.unique_name("sim2real-ns-")

    appsync.create_channel_namespace(apiId=api_id, name=ns_name)
    ctx.on_cleanup(lambda: appsync.delete_channel_namespace(apiId=api_id, name=ns_name))

    resp = appsync.list_channel_namespaces(apiId=api_id)
    names = [n["name"] for n in resp["channelNamespaces"]]
    assert ns_name in names, f"expected {ns_name} in {names}"

    # Distinct error boundary: unknown apiId.
    code, code_msg = _error(lambda: appsync.list_channel_namespaces(apiId=_BOGUS_API_ID))
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert code_msg == "API not found.", f"unexpected message: {code_msg!r}"



def _create_event_api(ctx) -> str:
    appsync = ctx.client("appsync")
    name = ctx.unique_name("sim2real-behav-")
    resp = appsync.create_api(
        name=name,
        eventConfig=_EVENT_CONFIG,
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )
    api_id = resp["api"]["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_api(apiId=api_id))
    return api_id


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
