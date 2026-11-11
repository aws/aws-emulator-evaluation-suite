"""tag-policy-exceeds-limit-rejected."""
from __future__ import annotations

import json
from typing import Any

from behavioral_harness import tags

CHECK = "tag-policy-exceeds-limit-rejected"
GROUP = "overly-permissive"
SERVICES = ["iam"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagPolicy with 51 tags is rejected with ValidationError and applies none of them, while a
    within-limit batch on the same policy succeeds."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-policy-limit-")
    doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
    }
    arn = iam.create_policy(PolicyName=name, PolicyDocument=json.dumps(doc))["Policy"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_policy(PolicyArn=arn))

    # Tags is modeled with maxItems=50, so 51 fails input validation (ValidationError)
    # before the resource-level LimitExceeded check runs.
    too_many = [{"Key": f"k{i}", "Value": f"v{i}"} for i in range(51)]
    code, message = _error(lambda: iam.tag_policy(PolicyArn=arn, Tags=too_many))
    assert code == "ValidationError", f"expected ValidationError, got {code}"
    expected = (
        "1 validation error detected: Value at 'tags' failed to satisfy constraint: "
        "Member must have length less than or equal to 50"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    after_reject = iam.list_policy_tags(PolicyArn=arn)["Tags"]
    assert after_reject == [], f"expected no tags applied after rejected TagPolicy, got {after_reject}"

    # Positive control: a within-limit batch on the same policy succeeds.
    ok_tags = [{"Key": "env", "Value": "test"}, {"Key": "owner", "Value": "platform"}]
    iam.tag_policy(PolicyArn=arn, Tags=ok_tags)
    listed = iam.list_policy_tags(PolicyArn=arn)["Tags"]
    assert {(t["Key"], t["Value"]) for t in listed} == {(t["Key"], t["Value"]) for t in ok_tags}, (
        f"expected tags {ok_tags} to apply, got {listed}"
    )


def _error(fn: Any) -> tuple[str, str]:
    """The (Error.Code, Error.Message) fn() raises; an unexpected success fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
