"""delete-resource-policy-nonexistent-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-resource-policy-nonexistent-rejected"
GROUP = "error-semantics"
SERVICES = ["rum"]

_NO_POLICY = "Resource policy does not exist"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteResourcePolicy on an app monitor with no attached policy fails with
    PolicyNotFoundException rather than returning success, while the same call on an app
    monitor that DOES have a policy attached succeeds (in-file positive control)."""
    rum = ctx.client("rum")

    # --- negative: no policy ever attached ---
    bare_name = _create_app_monitor(ctx)
    code, message = _client_error(lambda: rum.delete_resource_policy(Name=bare_name))
    assert code == "PolicyNotFoundException", f"expected PolicyNotFoundException, got {code}"
    assert message == _NO_POLICY, f"expected message {_NO_POLICY!r}, got {message!r}"
    # Effect absent: still no policy to read.
    still_missing, still_message = _client_error(lambda: rum.get_resource_policy(Name=bare_name))
    assert still_missing == "PolicyNotFoundException", (
        f"expected PolicyNotFoundException, got {still_missing}"
    )
    assert still_message == _NO_POLICY, f"expected message {_NO_POLICY!r}, got {still_message!r}"

    # --- positive control: a policy exists, delete succeeds ---
    controlled_name = _create_app_monitor(ctx)
    account_id = _account_id(ctx)
    arn = f"arn:aws:rum:{ctx.region}:{account_id}:appmonitor/{controlled_name}"
    policy_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "rum:PutRumEvents",
                    "Resource": arn,
                    "Principal": "*",
                }
            ],
        },
        separators=(",", ":"),
    )
    rum.put_resource_policy(Name=controlled_name, PolicyDocument=policy_doc)
    rum.delete_resource_policy(Name=controlled_name)  # must not raise
    after_delete, after_message = _client_error(lambda: rum.get_resource_policy(Name=controlled_name))
    assert after_delete == "PolicyNotFoundException", (
        f"expected policy to be gone after successful delete, got {after_delete}"
    )
    assert after_message == _NO_POLICY, f"expected message {_NO_POLICY!r}, got {after_message!r}"


def _create_app_monitor(ctx) -> str:
    rum = ctx.client("rum")
    name = ctx.unique_name("sim2real-behav-rum-")
    rum.create_app_monitor(Name=name, Domain="www.example.com")
    ctx.on_cleanup(lambda: rum.delete_app_monitor(Name=name))
    return name


def _account_id(ctx) -> str:
    sts = ctx.client("sts")
    return sts.get_caller_identity()["Account"]


def _client_error(fn):
    """Call fn and return the (code, message) of the ClientError it raises; a success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
