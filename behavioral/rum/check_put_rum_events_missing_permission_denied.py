"""put-rum-events-missing-permission-denied."""
from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-rum-events-missing-permission-denied"
GROUP = "overly-permissive"
SERVICES = ["rum"]


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A caller that should be denied rum:PutRumEvents by an explicit resource-policy Deny gets
    AccessDeniedException, ingestion is rejected (not silently accepted), and access is restored
    the moment the Deny is removed -- proving the rejection is policy-driven, not a broken pipeline.
    """
    rum = ctx.client("rum")
    sts = ctx.client("sts")

    app_name = ctx.unique_name("sim2real-rum-events-")
    identity = sts.get_caller_identity()
    account_id = identity["Account"]
    caller_arn = identity["Arn"]
    app_id = rum.create_app_monitor(
        Name=app_name, Domain="sim2real-behav.example.com", Tags={"Team": "rum-fidelity"}
    )["Id"]
    ctx.on_cleanup(lambda: rum.delete_app_monitor(Name=app_name))

    app_arn = f"arn:aws:rum:{ctx.region}:{account_id}:appmonitor/{app_name}"

    # Positive control #1: with no resource policy attached, the caller's own (broad) identity
    # permissions govern PutRumEvents, and the call succeeds.
    rum.put_rum_events(**_rum_events_kwargs(app_id, app_name))

    deny_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Action": "rum:PutRumEvents",
                "Resource": app_arn,
                "Principal": "*",
            }
        ],
    }
    rum.put_resource_policy(Name=app_name, PolicyDocument=json.dumps(deny_policy))
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: rum.delete_resource_policy(Name=app_name)))

    code, message = _poll_for_error(
        lambda: rum.put_rum_events(**_rum_events_kwargs(app_id, app_name)), timeout_s=240.0, interval_s=5.0
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code!r}"
    assert message == (
        f"User: {caller_arn} is not authorized to perform: rum:PutRumEvents on resource: "
        f"{app_id} with an explicit deny in a resource-based policy"
    ), message

    # Remove the Deny and confirm access is restored -- ties the rejection strictly to the policy.
    rum.delete_resource_policy(Name=app_name)
    _poll_until_succeeds(
        lambda: rum.put_rum_events(**_rum_events_kwargs(app_id, app_name)),
        "expected access restored after Deny removal",
        timeout_s=240.0,
        interval_s=5.0,
    )


# Resource-policy changes on RUM app monitors take time to reach the ingestion path (a removed
# Deny can keep refusing PutRumEvents for minutes), so the policy-driven outcomes are polled
# until they settle rather than graded on the first observation.
def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _poll_for_error(fn, *, timeout_s: float, interval_s: float):
    """Poll until fn() is refused; return the (code, message). A success keeps polling until the
    deadline, then raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return _client_error(fn)
        except AssertionError as exc:
            if time.monotonic() >= deadline:
                raise AssertionError(f"call was not refused within {timeout_s}s: {exc}") from None
        time.sleep(interval_s)


def _poll_until_succeeds(fn, failure: str, *, timeout_s: float, interval_s: float) -> None:
    """Poll until fn() succeeds; raise ``failure`` with the last refusal on timeout."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as err:
            if time.monotonic() >= deadline:
                raise AssertionError(f"{failure}: {err.response['Error']}") from None
        time.sleep(interval_s)


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("PolicyNotFoundException", "ResourceNotFoundException"):
            raise


def _rum_events_kwargs(app_id: str, app_name: str) -> dict:
    event_id = str(uuid.uuid4())
    return {
        "Id": app_id,
        "BatchId": str(uuid.uuid4()),
        "AppMonitorDetails": {"id": app_id, "name": app_name, "version": "1.0"},
        "UserDetails": {"sessionId": str(uuid.uuid4()), "userId": str(uuid.uuid4())},
        "RumEvents": [
            {
                "id": event_id,
                "timestamp": datetime.now(timezone.utc),
                "type": "com.amazon.rum.sim2real_event",
                "metadata": json.dumps({"version": "1.0.0", "domain": "sim2real-behav.example.com"}),
                "details": json.dumps({"message": "sim2real-behavioral-check"}),
            }
        ],
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
