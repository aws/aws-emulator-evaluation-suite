"""tags-round-trip-on-ip-group."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tags-round-trip-on-ip-group"
GROUP = "state"
SERVICES = ["workspaces"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTags/DescribeTags/DeleteTags round-trip on a WorkSpaces resource (an IP group).
    DeleteTags removes exactly the targeted key and leaves an untargeted tag untouched."""
    ws = ctx.client("workspaces")
    name = ctx.unique_name("sim2real-wsipg-tags-")
    group_id = ws.create_ip_group(GroupName=name, GroupDesc="sim2real tags test")["GroupId"]
    ctx.on_cleanup(lambda: _safe_delete_ip_group(ctx, group_id))

    # A tag that survives the whole check, so a tag-based cleanup finds this group if
    # cleanup does not run.
    ws.create_tags(ResourceId=group_id, Tags=[{"Key": "sim2real", "Value": "true"}])

    before = _tag_map(ws, group_id)
    assert "env" not in before, f"expected no 'env' tag on a freshly created group, got {before}"

    ws.create_tags(ResourceId=group_id, Tags=[{"Key": "env", "Value": "sim2real"}])
    tag_map = _tag_map(ws, group_id)
    assert tag_map.get("env") == "sim2real", f"tag not visible after CreateTags: {tag_map}"

    ws.delete_tags(ResourceId=group_id, TagKeys=["env"])
    tags_after = _tag_map(ws, group_id)
    assert "env" not in tags_after, f"tag still present after DeleteTags: {tags_after}"
    assert tags_after.get("sim2real") == "true", (
        f"DeleteTags disturbed an untargeted tag: {tags_after}"
    )


# ===== helpers =====
def _tag_map(ws, group_id: str) -> dict:
    return {t["Key"]: t["Value"] for t in ws.describe_tags(ResourceId=group_id)["TagList"]}


def _safe_delete_ip_group(ctx, group_id: str) -> None:
    from botocore.exceptions import ClientError

    ws = ctx.client("workspaces")
    try:
        ws.delete_ip_group(GroupId=group_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
