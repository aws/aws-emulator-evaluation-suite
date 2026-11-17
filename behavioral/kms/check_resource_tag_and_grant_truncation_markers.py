"""resource-tag-and-grant-truncation-markers."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "resource-tag-and-grant-truncation-markers"
GROUP = 'representation'
SERVICES = ['kms']


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListResourceTags and ListGrants carry Truncated False and omit NextMarker once a key
    holds exactly one tag or grant, and again once that one entry is removed.
    """
    kms = ctx.client("kms")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]

    key_id = kms.create_key(KeyUsage="ENCRYPT_DECRYPT", KeySpec="SYMMETRIC_DEFAULT")["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda _k=key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))

    no_tags = kms.list_resource_tags(KeyId=key_id)
    assert no_tags["Truncated"] is False, f"no tags: expected Truncated=False, got {no_tags.get('Truncated')!r}"
    assert "NextMarker" not in no_tags, f"no tags: expected no NextMarker, got {no_tags['NextMarker']!r}"
    assert no_tags["Tags"] == [], f"expected no tags on a fresh key, got {no_tags['Tags']!r}"

    tag_key = ctx.unique_name("sim2real-kms-marker-")
    tag_value = "single-entry"
    kms.tag_resource(KeyId=key_id, Tags=[{"TagKey": tag_key, "TagValue": tag_value}])

    one_tag = kms.list_resource_tags(KeyId=key_id)
    assert one_tag["Truncated"] is False, f"one tag: expected Truncated=False, got {one_tag.get('Truncated')!r}"
    assert "NextMarker" not in one_tag, f"one tag: expected no NextMarker, got {one_tag['NextMarker']!r}"
    found_tags = [(t["TagKey"], t["TagValue"]) for t in one_tag["Tags"]]
    assert found_tags == [(tag_key, tag_value)], f"expected exactly one tag {(tag_key, tag_value)!r}, got {found_tags!r}"

    kms.untag_resource(KeyId=key_id, TagKeys=[tag_key])

    tags_emptied = kms.list_resource_tags(KeyId=key_id)
    assert tags_emptied["Truncated"] is False, (
        f"emptied tags: expected Truncated=False, got {tags_emptied.get('Truncated')!r}"
    )
    assert "NextMarker" not in tags_emptied, (
        f"emptied tags: expected no NextMarker, got {tags_emptied['NextMarker']!r}"
    )
    assert tags_emptied["Tags"] == [], f"expected no tags after untag, got {tags_emptied['Tags']!r}"

    grantee = f"arn:aws:iam::{account}:root"
    grant_id = kms.create_grant(KeyId=key_id, GranteePrincipal=grantee, Operations=["Encrypt"])["GrantId"]

    one_grant = kms.list_grants(KeyId=key_id)
    assert one_grant["Truncated"] is False, f"one grant: expected Truncated=False, got {one_grant.get('Truncated')!r}"
    assert "NextMarker" not in one_grant, f"one grant: expected no NextMarker, got {one_grant['NextMarker']!r}"
    found_grants = [g["GrantId"] for g in one_grant["Grants"]]
    assert found_grants == [grant_id], f"expected exactly the one grant {grant_id!r}, got {found_grants!r}"

    kms.revoke_grant(KeyId=key_id, GrantId=grant_id)

    grants_emptied = kms.list_grants(KeyId=key_id)
    assert grants_emptied["Truncated"] is False, (
        f"emptied grants: expected Truncated=False, got {grants_emptied.get('Truncated')!r}"
    )
    assert "NextMarker" not in grants_emptied, (
        f"emptied grants: expected no NextMarker, got {grants_emptied['NextMarker']!r}"
    )
    assert grants_emptied["Grants"] == [], f"expected no grants after revoke, got {grants_emptied['Grants']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
