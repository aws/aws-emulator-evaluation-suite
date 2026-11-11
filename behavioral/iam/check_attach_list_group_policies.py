"""attach-list-group-policies."""
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

CHECK = "attach-list-group-policies"
GROUP = 'attach_detach'
SERVICES = ['iam']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AttachGroupPolicy -> ListAttachedGroupPolicies shows the attachment, and only it."""
    iam = ctx.client("iam")
    group = ctx.unique_name("sim2real-behav-grp-")
    iam.create_group(GroupName=group, Path="/")
    ctx.on_cleanup(lambda n=group: iam.delete_group(GroupName=n))

    before = iam.list_attached_group_policies(GroupName=group)["AttachedPolicies"]
    assert before == [], f"expected a freshly created group to have no attached policies, got {before}"

    arn = iam.create_policy(
        PolicyName=ctx.unique_name("sim2real-behav-pol-"),
        PolicyDocument=MINIMAL_POLICY_DOCUMENT,
        Path="/",
        Tags=[{"Key": "sim2real", "Value": "attach-list-group-policies"}],
    )["Policy"]["Arn"]
    ctx.on_cleanup(lambda a=arn: iam.delete_policy(PolicyArn=a))
    iam.attach_group_policy(GroupName=group, PolicyArn=arn)
    ctx.on_cleanup(lambda g=group, p=arn: iam.detach_group_policy(GroupName=g, PolicyArn=p))

    resp = iam.list_attached_group_policies(GroupName=group)
    attached_arns = [p["PolicyArn"] for p in resp["AttachedPolicies"]]
    assert attached_arns == [arn], f"expected exactly [{arn}] attached, got {attached_arns}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
