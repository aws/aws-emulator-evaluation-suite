"""create-channel-namespace-invalid-auth-mode-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-channel-namespace-invalid-auth-mode-rejected"
GROUP = "overly-permissive"
SERVICES = ["appsync"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateChannelNamespace is rejected when an auth mode is not among the parent
    Event API's authentication providers, and does not create a partially-usable
    namespace; a namespace whose auth mode DOES match a provider still succeeds.
    """
    appsync = ctx.client("appsync")

    api_name = ctx.unique_name("sim2real-appsync-eventapi-")
    event_config = {
        "authProviders": [{"authType": "API_KEY"}],
        "connectionAuthModes": [{"authType": "API_KEY"}],
        "defaultPublishAuthModes": [{"authType": "API_KEY"}],
        "defaultSubscribeAuthModes": [{"authType": "API_KEY"}],
    }
    api = appsync.create_api(
        name=api_name, eventConfig=event_config, tags={"sim2real": "true"}
    )["api"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_api(apiId=api_id))

    # Break exactly one thing: request AWS_IAM auth, which the Api's authProviders
    # (API_KEY only) do not permit.
    bad_ns_name = ctx.unique_name("sim2real-ns-bad-")
    code, message = _error(
        lambda: appsync.create_channel_namespace(
            apiId=api_id,
            name=bad_ns_name,
            subscribeAuthModes=[{"authType": "AWS_IAM"}],
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    assert message == "Channel namespace auth type must be present in the API's auth providers.", (
        f"expected the exact auth-mode refusal message, got {message!r}"
    )

    # Effect is absent: no namespace with that name exists on the Api.
    listed = appsync.list_channel_namespaces(apiId=api_id)["channelNamespaces"]
    assert all(ns["name"] != bad_ns_name for ns in listed), (
        f"rejected namespace {bad_ns_name} appeared in list_channel_namespaces"
    )
    not_found_code, not_found_message = _error(
        lambda: appsync.get_channel_namespace(apiId=api_id, name=bad_ns_name)
    )
    assert not_found_code == "NotFoundException", (
        f"expected NotFoundException, got {not_found_code}"
    )
    assert not_found_message == "Channel namespace not found.", (
        f"expected the exact NotFound message, got {not_found_message!r}"
    )

    # Positive control: the exact same shape of request, but with an auth mode the
    # Api's authProviders DO permit, succeeds.
    good_ns_name = ctx.unique_name("sim2real-ns-good-")
    ns = appsync.create_channel_namespace(
        apiId=api_id,
        name=good_ns_name,
        subscribeAuthModes=[{"authType": "API_KEY"}],
        tags={"sim2real": "true"},
    )["channelNamespace"]
    ctx.on_cleanup(lambda: appsync.delete_channel_namespace(apiId=api_id, name=good_ns_name))
    assert ns["name"] == good_ns_name, f"expected {good_ns_name}, got {ns['name']}"

    # Terminal read: independent of the create call that just succeeded, confirming
    # the namespace both exists and carries the auth mode that was accepted.
    fetched = appsync.get_channel_namespace(apiId=api_id, name=good_ns_name)["channelNamespace"]
    assert fetched["subscribeAuthModes"] == [{"authType": "API_KEY"}], (
        f"expected subscribeAuthModes [API_KEY], got {fetched['subscribeAuthModes']}"
    )


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
