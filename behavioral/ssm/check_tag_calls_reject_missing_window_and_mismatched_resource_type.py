"""tag-calls-reject-missing-window-and-mismatched-resource-type."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-calls-reject-missing-window-and-mismatched-resource-type"
GROUP = "overly-permissive"
SERVICES = ["ssm"]


def _error(fn):
    """The (code, message) ``fn`` raises; an unexpected success raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Tag calls on a missing window id or under a mismatched ResourceType are refused.

    A missing id answers InvalidResourceId; a mismatched ResourceType answers ValidationException
    naming the id format it expects for that type. Either way the window's tags stay as created.
    """
    ssm = ctx.client("ssm")
    created_tags = [{"Key": "owner", "Value": "alpha"}]

    window_id = ssm.create_maintenance_window(
        Name=ctx.unique_name("sim2real-behav-tagneg-mw-"),
        Schedule="rate(7 days)",
        Duration=2,
        Cutoff=1,
        AllowUnassociatedTargets=False,
        Tags=created_tags,
    )["WindowId"]
    ctx.on_cleanup(lambda: ssm.delete_maintenance_window(WindowId=window_id))

    def window_tags():
        return ssm.list_tags_for_resource(ResourceType="MaintenanceWindow", ResourceId=window_id)[
            "TagList"
        ]

    assert window_tags() == created_tags, f"control: window tags are {window_tags()!r}"

    missing_id = "mw-0123456789abcdef0"
    code, message = _error(
        lambda: ssm.list_tags_for_resource(ResourceType="MaintenanceWindow", ResourceId=missing_id)
    )
    assert (code, message) == ("InvalidResourceId", ""), (
        f"ListTagsForResource on a missing window gave {code!r}: {message!r}"
    )

    code, message = _error(
        lambda: ssm.add_tags_to_resource(
            ResourceType="PatchBaseline",
            ResourceId=window_id,
            Tags=[{"Key": "owner", "Value": "beta"}],
        )
    )
    # The mismatched ResourceType is refused by a format check against PatchBaseline's own id
    # pattern, ahead of any existence lookup.
    assert (code, message) == (
        "ValidationException",
        "resourceId should be in format pb-[0-9a-f]{17} for resource type PatchBaseline",
    ), f"AddTagsToResource with a mismatched ResourceType gave {code!r}: {message!r}"
    assert window_tags() == created_tags, (
        f"a refused AddTagsToResource changed the window's tags to {window_tags()!r}"
    )

    ssm.add_tags_to_resource(
        ResourceType="MaintenanceWindow",
        ResourceId=window_id,
        Tags=[{"Key": "owner", "Value": "beta"}],
    )
    assert window_tags() == [{"Key": "owner", "Value": "beta"}], (
        f"the same AddTagsToResource under the right type left tags {window_tags()!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
