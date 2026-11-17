"""list-instance-profile-tags-pagination-continuation."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-instance-profile-tags-pagination-continuation"
GROUP = "tagging"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListInstanceProfileTags with MaxItems=1 pages every tag exactly once via Marker, and
    UntagInstanceProfile drops only the untagged key from a later page read.
    """
    iam = ctx.client("iam")
    profile = ctx.unique_name("sim2real-behav-ip-")
    iam.create_instance_profile(InstanceProfileName=profile)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=profile))

    tag_set = {f"sim2real-k{i}-{profile}": f"v{i}" for i in range(3)}
    iam.tag_instance_profile(
        InstanceProfileName=profile,
        Tags=[{"Key": k, "Value": v} for k, v in tag_set.items()],
    )

    first_page = iam.list_instance_profile_tags(InstanceProfileName=profile, MaxItems=1)
    assert len(first_page["Tags"]) == 1, f"expected 1 tag with MaxItems=1, got {first_page['Tags']!r}"
    assert first_page["IsTruncated"] is True, (
        f"expected IsTruncated=True with 3 tags and MaxItems=1, got {first_page['IsTruncated']!r}"
    )
    assert "Marker" in first_page and first_page["Marker"], (
        f"expected a non-empty Marker on a truncated page, got {first_page.get('Marker')!r}"
    )

    collected = list(first_page["Tags"])
    marker = first_page["Marker"]
    for _ in range(len(tag_set) + 2):
        page = iam.list_instance_profile_tags(InstanceProfileName=profile, MaxItems=1, Marker=marker)
        collected.extend(page["Tags"])
        if not page["IsTruncated"]:
            break
        marker = page["Marker"]
    else:
        raise AssertionError("pagination did not terminate within the expected number of pages")

    collected_map = {t["Key"]: t["Value"] for t in collected}
    assert collected_map == tag_set, f"expected {tag_set!r} paged in full, got {collected_map!r}"
    assert len(collected) == len(tag_set), "pagination returned a duplicate tag entry"

    removed_key = next(iter(tag_set))
    iam.untag_instance_profile(InstanceProfileName=profile, TagKeys=[removed_key])
    remaining = iam.list_instance_profile_tags(InstanceProfileName=profile)["Tags"]
    remaining_map = {t["Key"]: t["Value"] for t in remaining}
    expected_remaining = {k: v for k, v in tag_set.items() if k != removed_key}
    assert remaining_map == expected_remaining, (
        f"expected {expected_remaining!r} after UntagInstanceProfile, got {remaining_map!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
