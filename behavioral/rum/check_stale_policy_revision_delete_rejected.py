"""stale-policy-revision-delete-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "stale-policy-revision-delete-rejected"
GROUP = "error-semantics"
SERVICES = ["rum"]
_POLICY_NOT_FOUND = "Resource policy does not exist"
_STALE_REVISION = "PolicyRevisionID must match the existing revision"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteResourcePolicy with a stale PolicyRevisionId is rejected with
    InvalidPolicyRevisionIdException, leaves the current policy intact, and a delete
    using the correct revision id still succeeds (positive control)."""
    rum = ctx.client("rum")
    sts = ctx.client("sts")
    name = _create_app_monitor(ctx)

    account_id = sts.get_caller_identity()["Account"]
    monitor_arn = f"arn:aws:rum:{ctx.region}:{account_id}:appmonitor/{name}"
    policy_v1 = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowV1",
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "rum:PutRumEvents",
                    "Resource": monitor_arn,
                }
            ],
        }
    )
    put1 = rum.put_resource_policy(Name=name, PolicyDocument=policy_v1)
    revision_1 = put1["PolicyRevisionId"]

    policy_v2 = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowV2",
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "rum:PutRumEvents",
                    "Resource": monitor_arn,
                }
            ],
        }
    )
    put2 = rum.put_resource_policy(Name=name, PolicyDocument=policy_v2, PolicyRevisionId=revision_1)
    revision_2 = put2["PolicyRevisionId"]
    assert revision_2 != revision_1, "PutResourcePolicy should mint a new revision id on each write"

    # Break exactly one thing: try to delete using the now-stale revision_1.
    err = _client_error(lambda: rum.delete_resource_policy(Name=name, PolicyRevisionId=revision_1))
    assert err["Code"] == "InvalidPolicyRevisionIdException", (
        f"expected InvalidPolicyRevisionIdException for a stale revision, got {err!r}"
    )
    assert err.get("Message") == _STALE_REVISION, (
        f"expected message {_STALE_REVISION!r}, got {err.get('Message')!r}"
    )

    # Effect absent: the current (v2) policy must still be intact and unremoved.
    still_there = rum.get_resource_policy(Name=name)
    assert json.loads(still_there["PolicyDocument"]) == json.loads(policy_v2)
    assert still_there["PolicyRevisionId"] == revision_2

    # Positive control: deleting with the correct current revision succeeds.
    rum.delete_resource_policy(Name=name, PolicyRevisionId=revision_2)
    after = _client_error(lambda: rum.get_resource_policy(Name=name))
    assert after["Code"] == "PolicyNotFoundException", (
        f"expected the policy to be gone after a correctly-revisioned delete, got {after!r}"
    )
    assert after.get("Message") == _POLICY_NOT_FOUND, (
        f"expected message {_POLICY_NOT_FOUND!r}, got {after.get('Message')!r}"
    )


def _client_error(fn) -> dict:
    """Call fn(); return the botocore Error dict (Code, Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_app_monitor(ctx, domain: str = "example.com") -> str:
    rum = ctx.client("rum")
    name = ctx.unique_name("sim2real-behav-rum-")
    rum.create_app_monitor(Name=name, Domain=domain, Tags={"sim2real:managed": "true"})
    ctx.on_cleanup(lambda: _safe_delete_app_monitor(rum, name))
    return name


def _safe_delete_app_monitor(rum, name: str) -> None:
    try:
        rum.delete_app_monitor(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
