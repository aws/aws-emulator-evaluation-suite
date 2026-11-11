"""delete-resource-policy-then-get-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-resource-policy-then-get-rejected"
GROUP = "state-machine"
SERVICES = ["rum"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After DeleteResourcePolicy succeeds, GetResourcePolicy on the same app monitor fails
    with PolicyNotFoundException (the policy is gone), not stale/leftover data."""
    name = _create_app_monitor(ctx)
    account_id = _account_id(ctx)
    arn = f"arn:aws:rum:{ctx.region}:{account_id}:appmonitor/{name}"
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

    rum = ctx.client("rum")
    rum.put_resource_policy(Name=name, PolicyDocument=policy_doc)

    # Sanity: policy is readable before deletion.
    before = rum.get_resource_policy(Name=name)
    assert before["PolicyDocument"] == policy_doc, (
        f"expected GetResourcePolicy to echo {policy_doc!r} before deletion, got {before['PolicyDocument']!r}"
    )

    rum.delete_resource_policy(Name=name)

    code, message = _client_error(lambda: rum.get_resource_policy(Name=name))
    assert code == "PolicyNotFoundException", f"expected PolicyNotFoundException, got {code}"
    assert message == "Resource policy does not exist", f"expected the no-policy message, got {message!r}"


def _create_app_monitor(ctx) -> str:
    rum = ctx.client("rum")
    name = ctx.unique_name("sim2real-behav-rum-")
    rum.create_app_monitor(
        Name=name,
        Domain="www.example.com",
        Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )
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
