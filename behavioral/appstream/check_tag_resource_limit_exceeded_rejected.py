"""tag-resource-limit-exceeded-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-limit-exceeded-rejected"
GROUP = "overly-permissive"
SERVICES = ["appstream"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource that would push a resource past 50 tags is rejected with
    LimitExceededException and leaves the 50 tags intact, while overwriting an existing key
    (net count unchanged) succeeds."""
    appstream = ctx.client("appstream")

    stack_name = ctx.unique_name("sim2real-appstream-stack-")
    arn = appstream.create_stack(Name=stack_name)["Stack"]["Arn"]
    ctx.on_cleanup(lambda: appstream.delete_stack(Name=stack_name))

    fifty_tags = {f"sim2real-tag-{i:02d}": "v" for i in range(50)}
    appstream.tag_resource(ResourceArn=arn, Tags=fifty_tags)

    tags = appstream.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert len(tags) == 50, f"expected 50 tags after initial fill, got {len(tags)}: {tags}"

    got = _error(lambda: appstream.tag_resource(ResourceArn=arn, Tags={"sim2real-tag-51": "v"}))
    expected_msg = (
        "The resource already has the maximum of 50 tags. "
        "Delete tags from the specified resource as needed."
    )
    assert got == ("LimitExceededException", expected_msg), got

    # effect absent: still exactly the original 50 tags, no 51st key present
    tags_after = appstream.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert len(tags_after) == 50, f"expected 50 tags after rejected TagResource, got {len(tags_after)}"
    assert "sim2real-tag-51" not in tags_after, f"rejected tag key leaked into: {tags_after}"

    # positive control: overwriting an existing key's value (net tag count unchanged) succeeds
    appstream.tag_resource(ResourceArn=arn, Tags={"sim2real-tag-00": "updated-value"})
    tags_final = appstream.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert len(tags_final) == 50, f"expected 50 tags after net-zero overwrite, got {len(tags_final)}"
    assert tags_final["sim2real-tag-00"] == "updated-value", f"overwrite did not take: {tags_final}"


def _error(fn):
    """Call fn(); return its botocore error code and message. An unexpected success raises, so
    accepting input AWS refuses never reads as an error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
