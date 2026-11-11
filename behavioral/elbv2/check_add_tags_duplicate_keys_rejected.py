"""add-tags-duplicate-keys-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "add-tags-duplicate-keys-rejected"
GROUP = "representation"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AddTags with two entries for the same Key fails with DuplicateTagKeys and the exact message and applies
    none of the request's tags, while an AddTags with unique keys on the same resource applies both."""
    elbv2 = ctx.client("elbv2")
    tg_arn = elbv2.create_target_group(
        Name=ctx.unique_name("sim2real-elbv2-tg-")[:32].rstrip("-"),
        TargetType="lambda",
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: elbv2.delete_target_group(TargetGroupArn=tg_arn))

    code, message = _error_code(
        lambda: elbv2.add_tags(
            ResourceArns=[tg_arn],
            Tags=[{"Key": "dup", "Value": "first"}, {"Key": "dup", "Value": "second"}],
        )
    )
    assert code == "DuplicateTagKeys", f"expected DuplicateTagKeys, got {code!r}"
    assert message == "Tag key 'dup' has two values, but tag keys must have exactly one value", message

    after_reject = elbv2.describe_tags(ResourceArns=[tg_arn])["TagDescriptions"][0]["Tags"]
    assert after_reject == [], f"a rejected duplicate-key AddTags call must apply nothing, got {after_reject!r}"

    # Positive control: unique keys on the same resource succeed.
    elbv2.add_tags(ResourceArns=[tg_arn], Tags=[{"Key": "env", "Value": "test"}, {"Key": "owner", "Value": "sim2real"}])
    after_accept = {t["Key"]: t["Value"] for t in elbv2.describe_tags(ResourceArns=[tg_arn])["TagDescriptions"][0]["Tags"]}
    assert after_accept == {"env": "test", "owner": "sim2real"}, (
        f"expected exactly the two tags applied by the follow-up AddTags call, got {after_accept!r}"
    )


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(
        f"expected AddTags with a duplicated Key to be rejected, but it succeeded: {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
