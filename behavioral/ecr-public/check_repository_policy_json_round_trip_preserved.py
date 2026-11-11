"""repository-policy-json-round-trip-preserved."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "repository-policy-json-round-trip-preserved"
GROUP = "server-side"
SERVICES = ["ecr-public"]


def _ecrpub_client(ctx):
    """ecr-public's control-plane API is served only from us-east-1, so the client pins that
    region; ctx.client keeps an emulator run on the emulator's endpoint."""
    return ctx.client("ecr-public", region="us-east-1")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A structurally complex IAM policy document set via SetRepositoryPolicy is
    returned by GetRepositoryPolicy with identical value fidelity (key ordering may
    differ but every statement, condition, and list must round-trip unchanged)."""
    ecr = _ecrpub_client(ctx)
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    name = ctx.unique_name("sim2real-behav-ecrp-policy-")
    ecr.create_repository(repositoryName=name)
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=name, force=True))

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowPullFromAnyone",
                "Effect": "Allow",
                "Principal": "*",
                "Action": [
                    "ecr-public:BatchCheckLayerAvailability",
                    "ecr-public:GetRepositoryPolicy",
                    "ecr-public:DescribeRepositories",
                    "ecr-public:DescribeImages",
                    "ecr-public:DescribeImageTags",
                ],
            },
            {
                "Sid": "AllowAccountToManagePolicy",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": [
                    "ecr-public:SetRepositoryPolicy",
                    "ecr-public:GetRepositoryPolicy",
                    "ecr-public:DeleteRepositoryPolicy",
                ],
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": account_id},
                    "ForAllValues:StringLike": {
                        "aws:TagKeys": ["team-*", "env-*"],
                    },
                    "Bool": {"aws:SecureTransport": "true"},
                },
            },
        ],
    }
    policy_text = json.dumps(policy)

    ecr.set_repository_policy(repositoryName=name, policyText=policy_text)
    fetched_text = ecr.get_repository_policy(repositoryName=name)["policyText"]
    fetched_policy = json.loads(fetched_text)

    assert fetched_policy == policy, f"policy mismatch: {fetched_policy!r} != {policy!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
