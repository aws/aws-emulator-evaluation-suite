"""tag-resource-and-list-tags-round-trip."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "tag-resource-and-list-tags-round-trip"
GROUP = "data-plane"
SERVICES = ["efs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource/UntagResource on an access point are reflected exactly by ListTagsForResource."""
    efs = ctx.client("efs")
    token = ctx.unique_name("sim2real-efs-fs-")
    fs_id = efs.create_file_system(CreationToken=token)["FileSystemId"]
    ctx.on_cleanup(lambda: _delete_fs_best_effort(efs, fs_id))
    _wait_fs_state(efs, fs_id, "available")

    ap_token = ctx.unique_name("sim2real-efs-ap-")
    ap_id = efs.create_access_point(ClientToken=ap_token, FileSystemId=fs_id)["AccessPointId"]
    ctx.on_cleanup(lambda: _delete_ap_best_effort(efs, ap_id))
    _wait_ap_state(efs, ap_id, "available")

    initial_tags = efs.list_tags_for_resource(ResourceId=ap_id)["Tags"]
    assert initial_tags == [], f"expected no tags on a freshly created access point, got {initial_tags!r}"

    efs.tag_resource(ResourceId=ap_id, Tags=[{"Key": "env", "Value": "sim2real"}, {"Key": "team", "Value": "qa"}])
    tags = {t["Key"]: t["Value"] for t in efs.list_tags_for_resource(ResourceId=ap_id)["Tags"]}
    assert tags == {"env": "sim2real", "team": "qa"}, f"expected tag_resource's two tags, got {tags!r}"

    efs.untag_resource(ResourceId=ap_id, TagKeys=["team"])
    tags_after = {t["Key"]: t["Value"] for t in efs.list_tags_for_resource(ResourceId=ap_id)["Tags"]}
    assert tags_after == {"env": "sim2real"}, f"expected 'team' removed by untag_resource, got {tags_after!r}"


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _wait_fs_state(efs, fs_id, state, timeout_s=180.0):
    return _poll_until(
        lambda: efs.describe_file_systems(FileSystemId=fs_id)["FileSystems"][0]["LifeCycleState"],
        lambda s: s == state,
        timeout_s=timeout_s,
        interval_s=5.0,
    )


def _wait_ap_state(efs, ap_id, state, timeout_s=120.0):
    return _poll_until(
        lambda: efs.describe_access_points(AccessPointId=ap_id)["AccessPoints"][0]["LifeCycleState"],
        lambda s: s == state,
        timeout_s=timeout_s,
        interval_s=3.0,
    )


def _delete_fs_best_effort(efs, fs_id):
    try:
        efs.delete_file_system(FileSystemId=fs_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "FileSystemNotFound":
            raise


def _delete_ap_best_effort(efs, ap_id):
    try:
        efs.delete_access_point(AccessPointId=ap_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "AccessPointNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
