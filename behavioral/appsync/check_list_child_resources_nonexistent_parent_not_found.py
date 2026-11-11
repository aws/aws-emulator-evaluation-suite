"""list-child-resources-nonexistent-parent-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("expected a ClientError, but the call succeeded")

def _assert_ok(fn, label):
    try:
        return fn()
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        raise AssertionError(
            f"{label}: expected success against a live apiId, got {code}"
        ) from exc

def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NotFoundException":
            raise

CHECK = "list-child-resources-nonexistent-parent-not-found"
GROUP = 'overly-permissive'
SERVICES = ['appsync']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Each child-resource List* operation succeeds against a live parent and returns
    NotFoundException for a well-formed but deleted apiId, so the boundary is existence, not format.
    """
    svc = ctx.client("appsync")
    api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-api-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: svc.delete_graphql_api(apiId=api_id)))

    # Channel namespaces belong to an Event API; ListChannelNamespaces 404s on a GraphQL apiId.
    event_config = {
        "authProviders": [{"authType": "API_KEY"}],
        "connectionAuthModes": [{"authType": "API_KEY"}],
        "defaultPublishAuthModes": [{"authType": "API_KEY"}],
        "defaultSubscribeAuthModes": [{"authType": "API_KEY"}],
    }
    event_api_id = svc.create_api(
        name=ctx.unique_name("sim2real-behav-appsync-evt-"),
        eventConfig=event_config,
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["api"]["apiId"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: svc.delete_api(apiId=event_api_id)))

    svc.create_type(apiId=api_id, definition="type Query { ping: String }", format="SDL")
    data_source = svc.create_data_source(
        apiId=api_id, name=ctx.unique_name("sim2real_ds_"), type="NONE"
    )["dataSource"]
    function = svc.create_function(
        apiId=api_id,
        name=ctx.unique_name("sim2real_fn_"),
        dataSourceName=data_source["name"],
        requestMappingTemplate="{}",
        responseMappingTemplate="$util.toJson($context.result)",
        functionVersion="2018-05-29",
    )["functionConfiguration"]
    function_id = function["functionId"]

    _assert_ok(lambda: svc.list_api_keys(apiId=api_id), "ListApiKeys positive control")
    _assert_ok(lambda: svc.list_data_sources(apiId=api_id), "ListDataSources positive control")
    _assert_ok(lambda: svc.list_functions(apiId=api_id), "ListFunctions positive control")
    _assert_ok(
        lambda: svc.list_resolvers(apiId=api_id, typeName="Query"),
        "ListResolvers positive control",
    )
    _assert_ok(
        lambda: svc.list_resolvers_by_function(apiId=api_id, functionId=function_id),
        "ListResolversByFunction positive control",
    )
    _assert_ok(
        lambda: svc.list_channel_namespaces(apiId=event_api_id),
        "ListChannelNamespaces positive control",
    )
    _assert_ok(
        lambda: svc.list_source_api_associations(apiId=api_id),
        "ListSourceApiAssociations positive control",
    )

    svc.delete_graphql_api(apiId=api_id)
    svc.delete_api(apiId=event_api_id)

    code, message = _error(lambda: svc.list_api_keys(apiId=api_id))
    assert code == "NotFoundException", f"ListApiKeys: expected NotFoundException, got {code}"
    assert message == "API not found.", f"ListApiKeys: unexpected message {message!r}"

    code, message = _error(lambda: svc.list_data_sources(apiId=api_id))
    assert code == "NotFoundException", f"ListDataSources: expected NotFoundException, got {code}"
    assert message == "API not found.", f"ListDataSources: unexpected message {message!r}"

    code, message = _error(lambda: svc.list_functions(apiId=api_id))
    assert code == "NotFoundException", f"ListFunctions: expected NotFoundException, got {code}"
    assert message == "API not found.", f"ListFunctions: unexpected message {message!r}"

    code, message = _error(lambda: svc.list_resolvers(apiId=api_id, typeName="Query"))
    assert code == "NotFoundException", f"ListResolvers: expected NotFoundException, got {code}"
    assert message == "API not found.", f"ListResolvers: unexpected message {message!r}"

    code, message = _error(
        lambda: svc.list_resolvers_by_function(apiId=api_id, functionId=function_id)
    )
    assert code == "NotFoundException", f"ListResolversByFunction: expected NotFoundException, got {code}"
    assert message == "API not found.", f"ListResolversByFunction: unexpected message {message!r}"

    code, message = _error(lambda: svc.list_channel_namespaces(apiId=event_api_id))
    assert code == "NotFoundException", f"ListChannelNamespaces: expected NotFoundException, got {code}"
    assert message == "API not found.", f"ListChannelNamespaces: unexpected message {message!r}"

    code, message = _error(lambda: svc.list_source_api_associations(apiId=api_id))
    assert code == "NotFoundException", f"ListSourceApiAssociations: expected NotFoundException, got {code}"
    assert message == "API not found.", f"ListSourceApiAssociations: unexpected message {message!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
