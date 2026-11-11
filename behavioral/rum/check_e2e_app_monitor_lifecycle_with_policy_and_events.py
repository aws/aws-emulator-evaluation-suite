"""e2e-app-monitor-lifecycle-with-policy-and-events."""
from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-app-monitor-lifecycle-with-policy-and-events"
GROUP = "e2e"
SERVICES = ["rum"]


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Full lifecycle: create, attach a resource policy, ingest events, verify the policy,
    detach it, delete the monitor, and confirm it 404s afterward -- consequences, not statuses."""
    rum = ctx.client("rum")
    sts = ctx.client("sts")

    name = ctx.unique_name("sim2real-behav-rum-e2e-")
    create_resp = rum.create_app_monitor(
        Name=name, Domain="example.com", Tags={"Team": "rum-fidelity"}
    )
    app_id = create_resp["Id"]
    ctx.on_cleanup(lambda: _safe_delete_app_monitor(rum, name))

    account_id = sts.get_caller_identity()["Account"]
    policy_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "rum:PutRumEvents",
                    "Resource": f"arn:aws:rum:{ctx.region}:{account_id}:appmonitor/{name}",
                }
            ],
        }
    )
    put_resp = rum.put_resource_policy(Name=name, PolicyDocument=policy_doc)
    revision_id = put_resp["PolicyRevisionId"]

    # Ingest an event -- the app monitor must be usable, not merely described.
    rum.put_rum_events(
        Id=app_id,
        BatchId=str(uuid.uuid4()),
        AppMonitorDetails={"id": app_id, "version": "1.0"},
        UserDetails={"sessionId": str(uuid.uuid4()), "userId": str(uuid.uuid4())},
        RumEvents=[
            {
                "id": str(uuid.uuid4()),
                "timestamp": datetime.now(timezone.utc),
                "type": "com.amazon.rum.custom_event",
                "metadata": json.dumps({"version": "1.0.0", "domain": "example.com"}),
                "details": json.dumps({"source": "e2e-lifecycle-check"}),
            }
        ],
    )

    # The policy is readable and matches what was set.
    got_policy = rum.get_resource_policy(Name=name)
    assert json.loads(got_policy["PolicyDocument"]) == json.loads(policy_doc), (
        f"expected policy document {policy_doc}, got {got_policy['PolicyDocument']}"
    )
    assert got_policy["PolicyRevisionId"] == revision_id, (
        f"expected revision {revision_id}, got {got_policy['PolicyRevisionId']}"
    )

    # Detach the policy.
    rum.delete_resource_policy(Name=name, PolicyRevisionId=revision_id)
    code_after_detach, message_after_detach = _client_error(lambda: rum.get_resource_policy(Name=name))
    assert code_after_detach == "PolicyNotFoundException", (
        f"expected PolicyNotFoundException after detach, got {code_after_detach}"
    )
    assert message_after_detach == "Resource policy does not exist", message_after_detach

    # Delete the app monitor and confirm it eventually 404s.
    rum.delete_app_monitor(Name=name)
    final_code, final_message = _poll_for_error(
        lambda: rum.get_app_monitor(Name=name), timeout_s=60.0, interval_s=2.0
    )
    assert final_code == "ResourceNotFoundException", (
        f"app monitor {name} did not 404 after deletion, last code was {final_code}"
    )
    assert final_message == f"Resource not found {name}", final_message


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        error = e.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _safe_delete_app_monitor(rum, name: str) -> None:
    try:
        rum.delete_app_monitor(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
