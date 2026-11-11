"""attachment-count-increments."""
from __future__ import annotations

import json

from behavioral_harness import tags

MINIMAL_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)

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

CHECK = "attachment-count-increments"
GROUP = 'attach_detach'
SERVICES = ['iam']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AttachmentCount on policy metadata tracks the live number of entities the policy is
    attached to: it rises by one per attach and falls by one per detach — not a fixed 0-or-1."""
    iam = ctx.client("iam")
    arn = iam.create_policy(PolicyName=ctx.unique_name("sim2real-behav-pol-"), PolicyDocument=MINIMAL_POLICY_DOCUMENT, Path="/")["Policy"]["Arn"]
    ctx.on_cleanup(lambda a=arn: iam.delete_policy(PolicyArn=a))

    def attachment_count() -> int:
        return iam.get_policy(PolicyArn=arn)["Policy"]["AttachmentCount"]

    before = attachment_count()
    assert before == 0, f"expected AttachmentCount 0 before any attachment, got {before}"

    role_a = ctx.unique_name("sim2real-behav-role-")
    iam.create_role(RoleName=role_a, AssumeRolePolicyDocument=MINIMAL_TRUST_POLICY, Path="/")
    ctx.on_cleanup(lambda n=role_a: iam.delete_role(RoleName=n))
    iam.attach_role_policy(RoleName=role_a, PolicyArn=arn)
    ctx.on_cleanup(lambda r=role_a, p=arn: iam.detach_role_policy(RoleName=r, PolicyArn=p))
    after_first = attachment_count()
    assert after_first == 1, f"expected AttachmentCount 1 after first attach, got {after_first}"

    role_b = ctx.unique_name("sim2real-behav-role-")
    iam.create_role(RoleName=role_b, AssumeRolePolicyDocument=MINIMAL_TRUST_POLICY, Path="/")
    ctx.on_cleanup(lambda n=role_b: iam.delete_role(RoleName=n))
    iam.attach_role_policy(RoleName=role_b, PolicyArn=arn)
    ctx.on_cleanup(lambda r=role_b, p=arn: iam.detach_role_policy(RoleName=r, PolicyArn=p))
    after_second = attachment_count()
    assert after_second == 2, f"expected AttachmentCount 2 after second attach, got {after_second}"

    iam.detach_role_policy(RoleName=role_a, PolicyArn=arn)
    after_detach = attachment_count()
    assert after_detach == 1, f"expected AttachmentCount 1 after detaching one of two, got {after_detach}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
