"""put-resource-policy-then-get-reflects."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "put-resource-policy-then-get-reflects"
GROUP = "state-machine"
SERVICES = ["rum"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy stores a policy document that GetResourcePolicy returns byte-identical."""
    name = _create_app_monitor(ctx)
    account_id = _account_id(ctx)
    arn = f"arn:aws:rum:{ctx.region}:{account_id}:appmonitor/{name}"
    policy_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowRUMPutEvents",
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
    put_resp = rum.put_resource_policy(Name=name, PolicyDocument=policy_doc)
    assert put_resp["PolicyRevisionId"], f"expected a non-empty PolicyRevisionId, got {put_resp!r}"
    ctx.on_cleanup(lambda: rum.delete_resource_policy(Name=name))

    get_resp = rum.get_resource_policy(Name=name)
    assert get_resp["PolicyDocument"] == policy_doc, (
        f"expected byte-identical policy document, got {get_resp['PolicyDocument']!r} "
        f"vs {policy_doc!r}"
    )
    assert get_resp["PolicyRevisionId"] == put_resp["PolicyRevisionId"], (
        f"expected GetResourcePolicy to report the same PolicyRevisionId as the put "
        f"({put_resp['PolicyRevisionId']!r}), got {get_resp['PolicyRevisionId']!r}"
    )


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
