"""e2e-list-visibility-after-partial-deletion."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-list-visibility-after-partial-deletion"
GROUP = "e2e"
SERVICES = ["cloudcontrol"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListResources reflects all created queues, then exactly the survivors after a subset is deleted."""
    cc = ctx.client("cloudcontrol")
    names = [ctx.unique_name(f"sim2real-behav-cc-list-{i}-") for i in range(3)]
    identifiers = []
    for name in names:
        desired_state = json.dumps({"QueueName": name, "Tags": [{"Key": "sim2real", "Value": CHECK}]})
        resp = cc.create_resource(TypeName="AWS::SQS::Queue", DesiredState=desired_state)
        event = _wait_for_progress(ctx, resp["ProgressEvent"]["RequestToken"])
        assert event["OperationStatus"] == "SUCCESS", event
        identifiers.append(event["Identifier"])
    for ident in identifiers:
        ctx.on_cleanup(lambda i=ident: _delete_and_wait(ctx, i))

    ok, found = _poll_until_value(
        lambda: _list_all_identifiers(ctx, "AWS::SQS::Queue"),
        lambda f: set(identifiers) <= f,
        timeout_s=90,
        interval_s=3,
    )
    assert ok, (
        f"not all created queues appeared in ListResources: expected {sorted(identifiers)}, "
        f"last seen {sorted(found or [])}"
    )

    deleted_id = identifiers[0]
    survivor_ids = set(identifiers[1:])
    _delete_and_wait(ctx, deleted_id)

    ok, found = _poll_until_value(
        lambda: _list_all_identifiers(ctx, "AWS::SQS::Queue"),
        lambda f: deleted_id not in f and survivor_ids <= f,
        timeout_s=90,
        interval_s=3,
    )
    assert ok, (
        f"ListResources did not reflect the partial deletion as its consequence: "
        f"deleted_id={deleted_id!r} still present={deleted_id in (found or set())}, "
        f"survivors expected={sorted(survivor_ids)}, found={sorted(found or [])}"
    )


def _wait_for_progress(ctx, request_token, timeout_s=180.0, interval_s=2.0):
    cc = ctx.client("cloudcontrol")
    deadline = time.monotonic() + timeout_s
    event = None
    while time.monotonic() < deadline:
        event = cc.get_resource_request_status(RequestToken=request_token)["ProgressEvent"]
        if event["OperationStatus"] in ("SUCCESS", "FAILED", "CANCEL_COMPLETE"):
            return event
        time.sleep(interval_s)
    raise AssertionError(f"operation did not stabilize within {timeout_s}s, last event={event}")


def _delete_and_wait(ctx, identifier, type_name="AWS::SQS::Queue"):
    cc = ctx.client("cloudcontrol")
    try:
        resp = cc.delete_resource(TypeName=type_name, Identifier=identifier)
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    final = _wait_for_progress(ctx, resp["ProgressEvent"]["RequestToken"])
    if final["OperationStatus"] != "SUCCESS" and final.get("ErrorCode") != "NotFound":
        raise AssertionError(f"deleting {identifier} ended {final['OperationStatus']}: {final}")


def _list_all_identifiers(ctx, type_name, max_pages=40):
    cc = ctx.client("cloudcontrol")
    ids = set()
    token = None
    for _ in range(max_pages):
        kwargs = {"TypeName": type_name}
        if token:
            kwargs["NextToken"] = token
        resp = cc.list_resources(**kwargs)
        for desc in resp.get("ResourceDescriptions", []):
            ids.add(desc["Identifier"])
        token = resp.get("NextToken")
        if not token:
            break
    return ids


def _poll_until_value(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return True, last
        time.sleep(interval_s)
    return False, last


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
