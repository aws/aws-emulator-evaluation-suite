"""channel-namespace-crud-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "channel-namespace-crud-lifecycle"
GROUP = "state"
SERVICES = ["appsync"]

_EVENT_CONFIG = {
    # The update step below switches a channel namespace's subscribeAuthModes to
    # include AWS_IAM in addition to API_KEY. AppSync requires every auth type used
    # by a channel namespace to also be registered as an authProvider on the parent
    # Event Api (UpdateChannelNamespace otherwise fails with BadRequestException:
    # "Channel namespace auth type must be present in the API's"), so both auth
    # types must be present here.
    "authProviders": [{"authType": "API_KEY"}, {"authType": "AWS_IAM"}],
    "connectionAuthModes": [{"authType": "API_KEY"}],
    "defaultPublishAuthModes": [{"authType": "API_KEY"}],
    "defaultSubscribeAuthModes": [{"authType": "API_KEY"}],
}


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A ChannelNamespace under an Event Api goes through create -> get (fields
    persisted) -> update (lastModified advances, auth modes actually change) ->
    delete -> get (NotFoundException)."""
    appsync = ctx.client("appsync")
    api_id = _create_event_api(ctx)
    # ChannelNamespace names only allow letters, digits, and hyphens (no underscores) --
    # unlike e.g. data-source names, which follow GraphQL-identifier rules. Use a
    # hyphenated prefix so the generated name actually satisfies AppSync's naming
    # constraint instead of tripping a ValidationException on CreateChannelNamespace.
    ns_name = ctx.unique_name("sim2real-ns-")

    created = appsync.create_channel_namespace(
        apiId=api_id,
        name=ns_name,
        subscribeAuthModes=[{"authType": "API_KEY"}],
        publishAuthModes=[{"authType": "API_KEY"}],
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["channelNamespace"]
    assert created["name"] == ns_name, f"expected name={ns_name!r}, got {created['name']!r}"
    assert created["subscribeAuthModes"] == [{"authType": "API_KEY"}], (
        f"expected subscribeAuthModes=[API_KEY], got {created['subscribeAuthModes']!r}"
    )

    fetched = appsync.get_channel_namespace(apiId=api_id, name=ns_name)["channelNamespace"]
    assert fetched["channelNamespaceArn"] == created["channelNamespaceArn"], (
        f"expected channelNamespaceArn={created['channelNamespaceArn']!r}, "
        f"got {fetched['channelNamespaceArn']!r}"
    )
    first_modified = fetched["lastModified"]
    # botocore parses lastModified into an aware datetime.datetime, not a float; convert
    # to an epoch float so it can be compared against time.time()'s return value below.
    first_modified_epoch = (
        first_modified.timestamp() if hasattr(first_modified, "timestamp") else float(first_modified)
    )

    # Poll (bounded) until the wall clock has actually advanced past the
    # captured lastModified second, so the upcoming update is guaranteed to
    # land in a later second and therefore produce a strictly newer timestamp.
    _poll_until(
        lambda: time.time(),
        lambda now: now > first_modified_epoch,
        timeout_s=10.0,
        interval_s=0.5,
    )

    updated = appsync.update_channel_namespace(
        apiId=api_id,
        name=ns_name,
        subscribeAuthModes=[{"authType": "API_KEY"}, {"authType": "AWS_IAM"}],
    )["channelNamespace"]
    assert len(updated["subscribeAuthModes"]) == 2, updated
    assert updated["lastModified"] > first_modified, (
        f"expected lastModified to strictly advance on update: "
        f"first={first_modified} updated={updated['lastModified']}"
    )

    appsync.delete_channel_namespace(apiId=api_id, name=ns_name)
    code, message = _error(lambda: appsync.get_channel_namespace(apiId=api_id, name=ns_name))
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert message == "Channel namespace not found.", (
        f"expected AWS's exact not-found message, got {message!r}"
    )


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises,
    because a target that accepts a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _create_event_api(ctx):
    appsync = ctx.client("appsync")
    resp = appsync.create_api(
        name=ctx.unique_name("sim2real-behav-"),
        eventConfig=_EVENT_CONFIG,
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )
    api_id = resp["api"]["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_api(apiId=api_id))
    return api_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
