"""tag-resource-channel-namespace-reserved-key-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-channel-namespace-reserved-key-rejected"
GROUP = "overly-permissive"
SERVICES = ["appsync"]

_EVENT_CONFIG = {
    "authProviders": [{"authType": "API_KEY"}],
    "connectionAuthModes": [{"authType": "API_KEY"}],
    "defaultPublishAuthModes": [{"authType": "API_KEY"}],
    "defaultSubscribeAuthModes": [{"authType": "API_KEY"}],
}

_RESERVED_KEY_ERROR = (
    "BadRequestException",
    "Invalid tag key. Customers cannot set tag keys starting with aws: (case insensitive)",
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource on a ChannelNamespace ARN rejects a reserved aws: tag key with
    BadRequestException, leaving a tag applied just before undisturbed; ListTagsForResource,
    GetChannelNamespace and ListChannelNamespaces agree on the namespace's tags throughout."""
    appsync = ctx.client("appsync")
    api_id = _create_event_api(ctx)
    ns_name = ctx.unique_name("sim2real-ns-")

    ns = appsync.create_channel_namespace(
        apiId=api_id,
        name=ns_name,
        subscribeAuthModes=[{"authType": "API_KEY"}],
        publishAuthModes=[{"authType": "API_KEY"}],
        tags={"Team": "checkout"},
    )["channelNamespace"]
    ctx.on_cleanup(lambda: appsync.delete_channel_namespace(apiId=api_id, name=ns_name))
    ns_arn = ns["channelNamespaceArn"]

    # Positive control: an ordinary tag key is accepted on this same ARN.
    appsync.tag_resource(resourceArn=ns_arn, tags={"Env": "staging"})

    code, message = _error_code(
        lambda: appsync.tag_resource(resourceArn=ns_arn, tags={"aws:reserved": "x"})
    )
    assert (code, message) == _RESERVED_KEY_ERROR, f"expected {_RESERVED_KEY_ERROR!r}, got {(code, message)!r}"

    expected = {"Team": "checkout", "Env": "staging"}
    _assert_tags_everywhere(appsync, api_id, ns_name, ns_arn, expected)

    appsync.untag_resource(resourceArn=ns_arn, tagKeys=["Env"])
    expected_after = {"Team": "checkout"}
    _assert_tags_everywhere(appsync, api_id, ns_name, ns_arn, expected_after)


def _assert_tags_everywhere(appsync, api_id: str, ns_name: str, ns_arn: str, expected: dict) -> None:
    """The reserved-key rejection left no trace, and every tag-reading surface agrees."""
    listed_tags = appsync.list_tags_for_resource(resourceArn=ns_arn)["tags"]
    assert listed_tags == expected, f"ListTagsForResource: expected {expected!r}, got {listed_tags!r}"

    fetched = appsync.get_channel_namespace(apiId=api_id, name=ns_name)["channelNamespace"]
    assert fetched.get("tags") == expected, f"GetChannelNamespace: expected {expected!r}, got {fetched.get('tags')!r}"

    found = _find_channel_namespace(appsync, api_id, ns_name)
    assert found.get("tags") == expected, f"ListChannelNamespaces: expected {expected!r}, got {found.get('tags')!r}"


def _find_channel_namespace(appsync, api_id: str, ns_name: str) -> dict:
    paginator = appsync.get_paginator("list_channel_namespaces")
    for page in paginator.paginate(apiId=api_id):
        for ns in page["channelNamespaces"]:
            if ns["name"] == ns_name:
                return ns
    raise AssertionError(f"channel namespace {ns_name!r} not found in ListChannelNamespaces")


def _create_event_api(ctx):
    appsync = ctx.client("appsync")
    resp = appsync.create_api(name=ctx.unique_name("sim2real-behav-"), eventConfig=_EVENT_CONFIG)
    api_id = resp["api"]["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_api(apiId=api_id))
    return api_id


def _error_code(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
