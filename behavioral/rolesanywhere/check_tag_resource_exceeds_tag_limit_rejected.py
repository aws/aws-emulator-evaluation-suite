"""tag-resource-exceeds-tag-limit-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-exceeds-tag-limit-rejected"
GROUP = "overly-permissive"
SERVICES = ["rolesanywhere"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource on a profile already at 50 user tags is refused with ValidationException ("The
    resultant tag set must not have more than 50 user tags.") and stores nothing; after an
    UntagResource the same profile accepts a new tag.
    """
    ra = ctx.client("rolesanywhere")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    role_arn = f"arn:aws:iam::{account_id}:role/{ctx.unique_name('sim2real-ra-role-')}"

    max_tags = [{"key": f"sim2real-ra-tag-{i}", "value": "v"} for i in range(50)]
    profile = ra.create_profile(
        name=ctx.unique_name("sim2real-ra-profile-"),
        roleArns=[role_arn],
        tags=max_tags,
    )["profile"]
    profile_id = profile["profileId"]
    profile_arn = profile["profileArn"]
    ctx.on_cleanup(lambda: ra.delete_profile(profileId=profile_id))

    tags_before = ra.list_tags_for_resource(resourceArn=profile_arn)["tags"]
    assert len(tags_before) == 50, f"expected the profile to start at the 50-tag quota, got {len(tags_before)}"

    error = _client_error(
        lambda: ra.tag_resource(resourceArn=profile_arn, tags=[{"key": "one-too-many", "value": "v"}])
    )
    assert error["Code"] == "ValidationException", f"unexpected code: {error['Code']!r}"
    expected_message = "The resultant tag set must not have more than 50 user tags."
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    tags_after = ra.list_tags_for_resource(resourceArn=profile_arn)["tags"]
    assert len(tags_after) == 50, f"expected the rejected call to leave the tag count unchanged at 50, got {len(tags_after)}"
    assert not any(t["key"] == "one-too-many" for t in tags_after), "rejected tag 'one-too-many' must not be persisted"

    # Positive control: freeing a slot then tagging again succeeds.
    ra.untag_resource(resourceArn=profile_arn, tagKeys=["sim2real-ra-tag-0"])
    ra.tag_resource(resourceArn=profile_arn, tags=[{"key": "now-fits", "value": "v"}])
    tags_final = {t["key"] for t in ra.list_tags_for_resource(resourceArn=profile_arn)["tags"]}
    assert "now-fits" in tags_final, f"expected 'now-fits' to be tagged once a slot was freed, got keys {tags_final!r}"
    assert "sim2real-ra-tag-0" not in tags_final, f"expected 'sim2real-ra-tag-0' to be removed by untag_resource, got keys {tags_final!r}"


def _client_error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
