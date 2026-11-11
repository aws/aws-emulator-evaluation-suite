"""remove-tags-then-verify-and-reject-missing-resource."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "remove-tags-then-verify-and-reject-missing-resource"
GROUP = "error-semantics"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RemoveTags deletes only the specified TagKeys from a resource (success path) and
    rejects a ResourceArns entry that does not exist (TargetGroupNotFound)."""
    elbv2 = ctx.client("elbv2")

    tg_arn = elbv2.create_target_group(
        Name=ctx.unique_name("sim2real-rmtags-tg-"),
        TargetType="lambda",
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: elbv2.delete_target_group(TargetGroupArn=tg_arn))

    elbv2.add_tags(
        ResourceArns=[tg_arn],
        Tags=[
            {"Key": "env", "Value": "test"},
            {"Key": "owner", "Value": "sim2real"},
        ],
    )
    before = _tags_for(elbv2, tg_arn)
    assert before == {"env": "test", "owner": "sim2real"}, before

    # --- success path: remove one of the two tag keys ---
    elbv2.remove_tags(ResourceArns=[tg_arn], TagKeys=["env"])

    after = _tags_for(elbv2, tg_arn)
    assert "env" not in after, after
    assert after.get("owner") == "sim2real", after

    # --- error boundary: RemoveTags rejects a nonexistent target group ARN ---
    bogus_arn = _fake_target_group_arn(tg_arn)
    code, message = _error(
        lambda: elbv2.remove_tags(ResourceArns=[bogus_arn], TagKeys=["owner"])
    )
    assert code == "TargetGroupNotFound", f"expected TargetGroupNotFound, got {code}"
    expected = f"Target groups '{bogus_arn}' not found"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # the real resource's remaining tag must be untouched by the rejected call
    still_there = _tags_for(elbv2, tg_arn)
    assert still_there.get("owner") == "sim2real", still_there



def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _tags_for(elbv2, resource_arn: str) -> dict[str, str]:
    desc = elbv2.describe_tags(ResourceArns=[resource_arn])["TagDescriptions"][0]
    return {t["Key"]: t["Value"] for t in desc["Tags"]}


def _fake_target_group_arn(real_arn: str) -> str:
    # Keep the same account/region prefix, swap in a name+id that was never created.
    prefix = real_arn.rsplit("/", 2)[0]
    return f"{prefix}/sim2real-nonexistent-tg/0123456789abcdef"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
