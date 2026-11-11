"""create-get-policy."""

from __future__ import annotations

import json

from behavioral_harness import tags

MINIMAL_POLICY_DOCUMENT = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "iam:GetUser",
                "Resource": "arn:aws:iam::*:user/sim2real-behav-*",
            }
        ],
    }
)

CHECK = "create-get-policy"
GROUP = "policy_lifecycle"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreatePolicy -> GetPolicy returns consistent metadata."""
    iam = ctx.client("iam")
    arn = iam.create_policy(
        PolicyName=ctx.unique_name("sim2real-behav-pol-"),
        PolicyDocument=MINIMAL_POLICY_DOCUMENT,
        Path="/",
    )["Policy"]["Arn"]
    ctx.on_cleanup(lambda a=arn: iam.delete_policy(PolicyArn=a))
    resp = iam.get_policy(PolicyArn=arn)
    policy = resp["Policy"]
    assert policy["Arn"] == arn, f"expected Arn {arn}, got {policy['Arn']}"
    assert policy["DefaultVersionId"] == "v1", (
        f"expected DefaultVersionId v1, got {policy['DefaultVersionId']}"
    )
    assert policy["AttachmentCount"] == 0, (
        f"expected AttachmentCount 0, got {policy['AttachmentCount']}"
    )
    assert policy["IsAttachable"] is True, (
        f"expected IsAttachable True, got {policy['IsAttachable']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
