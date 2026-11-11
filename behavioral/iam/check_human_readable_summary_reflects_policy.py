"""human-readable-summary-reflects-policy."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "human-readable-summary-reflects-policy"
GROUP = "server-side"
SERVICES = ["iam"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetHumanReadableSummary on an existing customer-managed policy ARN fails with
    ValidationError and the exact "Invalid resource type in ARN" message: it accepts only
    delegation-request ARNs."""
    iam = ctx.client("iam")
    policy_name = ctx.unique_name("sim2real-hrs-policy-")
    doc = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:PutObject"],
            "Resource": "arn:aws:s3:::sim2real-example-bucket/*",
        }],
    })
    policy_arn = iam.create_policy(PolicyName=policy_name, PolicyDocument=doc)["Policy"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_policy(PolicyArn=policy_arn))

    try:
        iam.get_human_readable_summary(EntityArn=policy_arn)
    except ClientError as e:
        code = e.response["Error"]["Code"]
        message = e.response["Error"]["Message"]
        assert code == "ValidationError", f"expected ValidationError for a policy ARN, got {code}: {message}"
        expected = "Invalid resource type in ARN"
        assert message == expected, (
            f"expected the resource-type-in-ARN rejection {expected!r}, got ValidationError with "
            f"message: {message!r}"
        )
    else:
        raise AssertionError("expected ValidationError for a policy ARN, but call succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
