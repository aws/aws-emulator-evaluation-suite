"""event-api-ops-reject-graphql-api-id."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "event-api-ops-reject-graphql-api-id"
GROUP = 'event-api'
SERVICES = ['appsync']

_EVENT_CONFIG = {
    "authProviders": [{"authType": "API_KEY"}],
    "connectionAuthModes": [{"authType": "API_KEY"}],
    "defaultPublishAuthModes": [{"authType": "API_KEY"}],
    "defaultSubscribeAuthModes": [{"authType": "API_KEY"}],
}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Event (v2) Api ids and GraphQL (v1) API ids are disjoint: GetApi and CreateChannelNamespace
    work on an Event Api id but fail NotFoundException on a GraphQL API id.
    """
    appsync = ctx.client("appsync")
    graphql_api_id = _create_graphql_api(ctx)["apiId"]
    event_api_id = _create_event_api(ctx)

    got = appsync.get_api(apiId=event_api_id)["api"]
    assert got["apiId"] == event_api_id, f"expected {event_api_id}, got {got['apiId']}"

    ns_name = ctx.unique_name("ns-control-")
    ns = appsync.create_channel_namespace(
        apiId=event_api_id,
        name=ns_name,
        subscribeAuthModes=[{"authType": "API_KEY"}],
        publishAuthModes=[{"authType": "API_KEY"}],
    )["channelNamespace"]
    ctx.on_cleanup(lambda: appsync.delete_channel_namespace(apiId=event_api_id, name=ns_name))
    assert ns["name"] == ns_name, f"expected {ns_name}, got {ns['name']}"

    code, message = _error(lambda: appsync.get_api(apiId=graphql_api_id))
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert message == "API not found.", f"unexpected GetApi message: {message!r}"

    code2, message2 = _error(
        lambda: appsync.create_channel_namespace(
            apiId=graphql_api_id,
            name="ns-on-graphql-api",
            subscribeAuthModes=[{"authType": "API_KEY"}],
            publishAuthModes=[{"authType": "API_KEY"}],
        )
    )
    assert code2 == "NotFoundException", f"expected NotFoundException, got {code2}"
    assert message2 == "API not found.", f"unexpected CreateChannelNamespace message: {message2!r}"



def _create_graphql_api(ctx) -> dict:
    """An API_KEY-auth GraphQL API. Sub-resources (data sources, functions,
    resolvers, types) are removed with their owning apiId, so only the API
    itself needs a teardown."""
    appsync = ctx.client("appsync")
    resp = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-api-"),
        authenticationType="API_KEY",
        tags={"sim2real": "behavioral"},
    )
    api = resp["graphqlApi"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api["apiId"]))
    return api


def _create_event_api(ctx) -> str:
    """A v2 Event Api used only as the positive control's genuine target."""
    appsync = ctx.client("appsync")
    resp = appsync.create_api(
        name=ctx.unique_name("sim2real-behav-appsync-eventapi-"),
        eventConfig=_EVENT_CONFIG,
        tags={"sim2real": "behavioral"},
    )
    api_id = resp["api"]["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_api(apiId=api_id))
    return api_id


def _error(fn):
    """Call fn() and return its botocore error (code, message); a call that succeeds raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
