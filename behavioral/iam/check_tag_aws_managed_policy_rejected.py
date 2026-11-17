"""tag-aws-managed-policy-rejected."""
from __future__ import annotations

import json
from typing import Any

from behavioral_harness import tags

CHECK = "tag-aws-managed-policy-rejected"
GROUP = "overly-permissive"
SERVICES = ["iam"]

_AWS_MANAGED_POLICY_ARN = "arn:aws:iam::aws:policy/ReadOnlyAccess"
_POLICY_DOC = json.dumps(
    {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "*"}]}
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagPolicy rejects an AWS managed policy's ARN, which this account does not own and
    cannot tag; the identical call on a customer-managed policy this check created succeeds."""
    iam = ctx.client("iam")

    code, message = _error(
        lambda: iam.tag_policy(
            PolicyArn=_AWS_MANAGED_POLICY_ARN, Tags=[{"Key": "env", "Value": "test"}]
        )
    )
    assert code == "InvalidInput", f"expected InvalidInput, got {code}"
    expected = "Tags not supported for policies in this domain"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control: the identical call on a customer-managed policy succeeds.
    policy_name = ctx.unique_name("sim2real-pol-tag-")
    policy_arn = iam.create_policy(PolicyName=policy_name, PolicyDocument=_POLICY_DOC)["Policy"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_policy(PolicyArn=policy_arn))
    iam.tag_policy(PolicyArn=policy_arn, Tags=[{"Key": "env", "Value": "test"}])
    listed = iam.list_policy_tags(PolicyArn=policy_arn)["Tags"]
    assert listed == [{"Key": "env", "Value": "test"}], f"expected the tag to apply, got {listed}"


def _error(fn: Any) -> tuple[str, str]:
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises, because an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects tagging an AWS managed policy, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
