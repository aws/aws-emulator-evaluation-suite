"""server-side-delete-resource-policy-idempotent-enforcement."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "server-side-delete-resource-policy-idempotent-enforcement"
GROUP = "server-side"
SERVICES = ["rum"]
_POLICY_NOT_FOUND = "Resource policy does not exist"
_DELETE_POLICY_NOT_FOUND = "Resource policy does not exist"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After DeleteResourcePolicy, every immediate GetResourcePolicy fails with PolicyNotFoundException
    and its exact message (no stale cached policy), and a second DeleteResourcePolicy is rejected with
    the same code and its exact delete message."""
    rum = ctx.client("rum")
    sts = ctx.client("sts")

    app_name = ctx.unique_name("sim2real-rum-policydel-")
    account_id = sts.get_caller_identity()["Account"]
    rum.create_app_monitor(Name=app_name, Domain="sim2real-behav.example.com")
    ctx.on_cleanup(lambda: rum.delete_app_monitor(Name=app_name))
    app_arn = f"arn:aws:rum:{ctx.region}:{account_id}:appmonitor/{app_name}"

    put = rum.put_resource_policy(Name=app_name, PolicyDocument=_policy_doc(app_arn))
    revision = put["PolicyRevisionId"]

    # Positive control: the policy is genuinely stored and independently readable
    # before we test its deletion -- otherwise a target whose GetResourcePolicy
    # always answers PolicyNotFoundException would pass the rest of this check
    # for free.
    before = rum.get_resource_policy(Name=app_name)
    assert before["PolicyRevisionId"] == revision, (
        f"expected the just-created policy to be readable with revision {revision!r} "
        f"before delete, got {before.get('PolicyRevisionId')!r}"
    )

    rum.delete_resource_policy(Name=app_name, PolicyRevisionId=revision)

    for attempt in range(5):
        err = _client_error(lambda: rum.get_resource_policy(Name=app_name))
        assert err["Code"] == "PolicyNotFoundException", (
            f"attempt {attempt}: expected PolicyNotFoundException immediately after delete, got {err!r}"
        )
        assert err.get("Message") == _POLICY_NOT_FOUND, (
            f"attempt {attempt}: expected message {_POLICY_NOT_FOUND!r}, got {err.get('Message')!r}"
        )

    second = _client_error(lambda: rum.delete_resource_policy(Name=app_name))
    assert second["Code"] == "PolicyNotFoundException", (
        f"expected PolicyNotFoundException on redundant delete, got {second!r}"
    )
    assert second.get("Message") == _DELETE_POLICY_NOT_FOUND, (
        f"expected message {_DELETE_POLICY_NOT_FOUND!r}, got {second.get('Message')!r}"
    )


def _client_error(fn) -> dict:
    """Call fn(); return the botocore Error dict (Code, Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _policy_doc(app_arn: str) -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "rum:PutRumEvents",
                    "Resource": app_arn,
                    "Principal": "*",
                }
            ],
        }
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
