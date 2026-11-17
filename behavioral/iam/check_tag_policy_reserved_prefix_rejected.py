"""tag-policy-reserved-prefix-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-policy-reserved-prefix-rejected"
GROUP = "overly-permissive"
SERVICES = ["iam"]

_DOCUMENT = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
    }
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagPolicy on a customer-managed policy accepts an ordinary tag key, then refuses a
    batch that mixes one with the AWS-reserved 'aws:' prefix, applying none of it.

    Reference: https://docs.aws.amazon.com/IAM/latest/APIReference/API_TagPolicy.html
    """
    iam = ctx.client("iam")
    policy_name = ctx.unique_name("sim2real-behav-policy-")
    policy = iam.create_policy(PolicyName=policy_name, PolicyDocument=_DOCUMENT)["Policy"]
    policy_arn = policy["Arn"]
    ctx.on_cleanup(lambda: iam.delete_policy(PolicyArn=policy_arn))

    iam.tag_policy(PolicyArn=policy_arn, Tags=[{"Key": "team", "Value": "payments"}])
    tags_after_first = {t["Key"]: t["Value"] for t in iam.list_policy_tags(PolicyArn=policy_arn)["Tags"]}
    assert tags_after_first == {"team": "payments"}, (
        f"expected the policy to carry only team=payments after the first TagPolicy call, "
        f"got {tags_after_first!r}"
    )

    mixed_batch = [
        {"Key": "stage", "Value": "canary"},
        {"Key": "aws:internal-marker", "Value": "blocked"},
    ]
    try:
        iam.tag_policy(PolicyArn=policy_arn, Tags=mixed_batch)
    except ClientError as exc:
        error = exc.response["Error"]
        assert error["Code"] == "InvalidInput", f"expected InvalidInput, got {error['Code']!r}"
        assert error["Message"] == "Tag keys beginning with aws: are reserved for system use.", (
            f"unexpected refusal message: {error['Message']!r}"
        )
    else:
        raise AssertionError(
            "TagPolicy accepted a batch containing an 'aws:'-prefixed key, but real AWS refuses "
            "the entire call"
        )

    tags_after_rejection = {t["Key"]: t["Value"] for t in iam.list_policy_tags(PolicyArn=policy_arn)["Tags"]}
    assert tags_after_rejection == tags_after_first, (
        f"a rejected TagPolicy call must leave the policy's tags untouched: "
        f"{tags_after_first!r} -> {tags_after_rejection!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
