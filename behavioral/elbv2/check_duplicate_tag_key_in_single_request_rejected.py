"""duplicate-tag-key-in-single-request-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "duplicate-tag-key-in-single-request-rejected"
GROUP = "representation"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AddTags with the same Key twice in one request fails with DuplicateTagKeys and applies no
    tags; a later well-formed AddTags on the same resource still succeeds."""
    elbv2 = ctx.client("elbv2")

    name = _short_name(ctx, "tg")
    tg = elbv2.create_target_group(Name=name, TargetType="lambda")["TargetGroups"][0]
    tg_arn = tg["TargetGroupArn"]
    ctx.on_cleanup(lambda: elbv2.delete_target_group(TargetGroupArn=tg_arn))

    code, message = _error_code(
        lambda: elbv2.add_tags(
            ResourceArns=[tg_arn],
            Tags=[{"Key": "dup", "Value": "a"}, {"Key": "dup", "Value": "b"}],
        )
    )
    assert code == "DuplicateTagKeys", f"expected DuplicateTagKeys, got {code!r}"
    assert message == "Tag key 'dup' has two values, but tag keys must have exactly one value", message

    described = elbv2.describe_tags(ResourceArns=[tg_arn])["TagDescriptions"][0]["Tags"]
    assert described == [], (
        f"a rejected duplicate-key AddTags call must apply none of its tags, got {described!r}"
    )

    elbv2.add_tags(ResourceArns=[tg_arn], Tags=[{"Key": "good", "Value": "yes"}])
    described2 = elbv2.describe_tags(ResourceArns=[tg_arn])["TagDescriptions"][0]["Tags"]
    tag_map2 = {t["Key"]: t["Value"] for t in described2}
    assert tag_map2.get("good") == "yes"


def _short_name(ctx, prefix: str) -> str:
    name = ctx.unique_name(f"{prefix}-").replace("_", "-")
    return name[:32].rstrip("-")


def _error_code(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"expected AddTags to reject the duplicate-key request, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
