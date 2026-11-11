"""repository-policy-json-preserved-exact."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "repository-policy-json-preserved-exact"
GROUP = "representation"
SERVICES = ["ecr-public"]


def _regional_client(ctx, service: str, region: str = "us-east-1"):
    """A ctx client for ``service``, pinned by default to us-east-1, the only ecr-public region."""
    return ctx.client(service, region=region)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetRepositoryPolicy/GetRepositoryPolicy preserve the parsed policy JSON, including Action
    list order and nested condition maps."""
    ecrp = _regional_client(ctx, "ecr-public")
    name = ctx.unique_name("sim2real-behav-policy-")
    ecrp.create_repository(repositoryName=name, tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: ecrp.delete_repository(repositoryName=name, force=True))

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowPublicPullWithCondition",
                "Effect": "Allow",
                "Principal": "*",
                "Action": [
                    "ecr-public:BatchCheckLayerAvailability",
                    "ecr-public:DescribeImages",
                    "ecr-public:DescribeImageTags",
                ],
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": "123456789012"},
                    "ArnLike": {"aws:SourceArn": "arn:aws:ecr-public:us-east-1:123456789012:*"},
                },
            }
        ],
    }
    # AWS re-serializes policyText with its own formatter and documents no key order, so the
    # policy is compared as parsed JSON.
    policy_text = json.dumps(policy, indent=4, sort_keys=False)

    set_resp = ecrp.set_repository_policy(repositoryName=name, policyText=policy_text)
    set_parsed = json.loads(set_resp["policyText"])
    assert set_parsed == policy, f"SetRepositoryPolicy echo mismatch: {set_parsed!r} != {policy!r}"

    get_resp = ecrp.get_repository_policy(repositoryName=name)
    get_parsed = json.loads(get_resp["policyText"])
    assert get_parsed == policy, f"policy mismatch: {get_parsed!r} != {policy!r}"

    statement = get_parsed["Statement"][0]
    assert statement["Sid"] == "AllowPublicPullWithCondition", statement
    assert statement["Action"] == [
        "ecr-public:BatchCheckLayerAvailability",
        "ecr-public:DescribeImages",
        "ecr-public:DescribeImageTags",
    ], statement["Action"]
    assert statement["Condition"]["StringEquals"]["aws:SourceAccount"] == "123456789012", statement[
        "Condition"
    ]
    assert (
        statement["Condition"]["ArnLike"]["aws:SourceArn"]
        == "arn:aws:ecr-public:us-east-1:123456789012:*"
    ), statement["Condition"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
