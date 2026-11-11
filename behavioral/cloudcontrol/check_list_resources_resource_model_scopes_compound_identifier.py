"""list-resources-resource-model-scopes-compound-identifier."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

TERMINAL_STATUSES = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _wait_terminal(cc, request_token, timeout_s=90, interval_s=2):
    """Poll GetResourceRequestStatus until the request reaches a terminal OperationStatus."""
    holder = {}

    def probe():
        resp = cc.get_resource_request_status(RequestToken=request_token)
        holder["event"] = resp["ProgressEvent"]
        return holder["event"]

    _poll_until(
        probe,
        lambda e: e is not None and e.get("OperationStatus") in TERMINAL_STATUSES,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description="request reaches a terminal OperationStatus",
    )
    return holder["event"]


def _delete_quiet(cc, type_name, identifier):
    """Teardown; DeleteResource is asynchronous, so poll the delete request to a terminal state."""
    try:
        resp = cc.delete_resource(TypeName=type_name, Identifier=identifier)
        _wait_terminal(cc, resp["ProgressEvent"]["RequestToken"], timeout_s=90, interval_s=2)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "RequestTokenNotFoundException",
            "ResourceNotFoundException",
            "TypeNotFoundException",
        ):
            raise


def _track(cc, ctx, type_name, identifier):
    ctx.on_cleanup(lambda: _delete_quiet(cc, type_name, identifier))


def _create_and_wait(cc, ctx, type_name, desired_state, track=True):
    resp = cc.create_resource(TypeName=type_name, DesiredState=desired_state)
    event = _wait_terminal(cc, resp["ProgressEvent"]["RequestToken"])
    if track and event.get("OperationStatus") == "SUCCESS":
        identifier = event.get("Identifier")
        if identifier:
            _track(cc, ctx, type_name, identifier)
    return event


def _get_resource(cc, type_name, identifier):
    return cc.get_resource(TypeName=type_name, Identifier=identifier)


def _properties(cc, type_name, identifier):
    """GetResource returns Properties as a JSON *string* -- decode it before asserting."""
    resp = _get_resource(cc, type_name, identifier)
    assert resp["ResourceDescription"]["Identifier"] == identifier, resp
    return json.loads(resp["ResourceDescription"]["Properties"])


def _log_group_desired_state(name):
    """RetentionInDays=1 is the cheapest retention; no events are written, so it costs nothing."""
    return json.dumps({"LogGroupName": name, "RetentionInDays": 1})


CHECK = "list-resources-resource-model-scopes-compound-identifier"
GROUP = 'lifecycle'
SERVICES = ['cloudcontrol']
LOG_GROUP_TYPE = "AWS::Logs::LogGroup"
LOG_STREAM_TYPE = "AWS::Logs::LogStream"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A LogStream's compound identifier is reported and accepted as "group|stream", and
    ListResources with a ResourceModel naming one log group excludes the other group's stream.
    """
    cc = ctx.client("cloudcontrol")
    group_a = ctx.unique_name("sim2real-behav-cc-loggroup-a-")
    group_b = ctx.unique_name("sim2real-behav-cc-loggroup-b-")
    stream_a = ctx.unique_name("sim2real-behav-cc-stream-a-")
    stream_b = ctx.unique_name("sim2real-behav-cc-stream-b-")

    # Cleanup is LIFO, and each resource registers at creation time, so streams are torn down
    # before their groups.
    for group in (group_a, group_b):
        event = _create_and_wait(cc, ctx, LOG_GROUP_TYPE, _log_group_desired_state(group))
        assert event["OperationStatus"] == "SUCCESS", f"log group {group} not created: {event}"

    identifiers = {}
    for group, stream in ((group_a, stream_a), (group_b, stream_b)):
        state = json.dumps({"LogGroupName": group, "LogStreamName": stream})
        event = _create_and_wait(cc, ctx, LOG_STREAM_TYPE, state)
        assert event["OperationStatus"] == "SUCCESS", f"log stream {stream} not created: {event}"
        expected = f"{group}|{stream}"
        assert event.get("Identifier") == expected, (
            f"a compound primary identifier must be reported delimited, "
            f"expected {expected!r}, got {event.get('Identifier')!r}"
        )
        identifiers[group] = expected

    props = _properties(cc, LOG_STREAM_TYPE, identifiers[group_a])
    assert props.get("LogGroupName") == group_a, props
    assert props.get("LogStreamName") == stream_a, props

    def listed(scope_group):
        """All identifiers ListResources returns for one ResourceModel scope, across pages."""
        found = set()
        kwargs = {
            "TypeName": LOG_STREAM_TYPE,
            "ResourceModel": json.dumps({"LogGroupName": scope_group}),
        }
        for _ in range(20):
            resp = cc.list_resources(**kwargs)
            found.update(d["Identifier"] for d in resp.get("ResourceDescriptions", []))
            next_token = resp.get("NextToken")
            if not next_token:
                break
            kwargs["NextToken"] = next_token
        return found

    for scope, other in ((group_a, group_b), (group_b, group_a)):
        found = _poll_until(
            lambda scope=scope: listed(scope),
            lambda ids, scope=scope: identifiers[scope] in ids,
            timeout_s=60,
            interval_s=2,
            description=f"ListResources scoped to {scope} surfaces its own stream",
        )
        assert identifiers[other] not in found, (
            f"ListResources scoped to {scope!r} leaked {identifiers[other]!r}; "
            f"ResourceModel must restrict the listing, returned {sorted(found)}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
