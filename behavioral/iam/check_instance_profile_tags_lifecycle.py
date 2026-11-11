"""instance-profile-tags-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "instance-profile-tags-lifecycle"
GROUP = "state-machine"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tagging an instance profile makes tags visible via ListInstanceProfileTags;
    untagging a single key removes only that key while an untouched key survives;
    untagging the remaining key clears the profile back to no tags."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-ip-")
    iam.create_instance_profile(InstanceProfileName=name)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=name))

    # Before tagging, no tags exist.
    initial = iam.list_instance_profile_tags(InstanceProfileName=name)["Tags"]
    assert initial == [], f"expected no tags before TagInstanceProfile, got {initial}"

    expected = [{"Key": "env", "Value": "test"}, {"Key": "team", "Value": "payments"}]
    _retry_until_visible(
        lambda: iam.tag_instance_profile(InstanceProfileName=name, Tags=expected)
    )

    listed = iam.list_instance_profile_tags(InstanceProfileName=name)["Tags"]
    assert {(t["Key"], t["Value"]) for t in listed} == {(t["Key"], t["Value"]) for t in expected}, (
        f"expected tags {expected}, got {listed}"
    )

    # Untagging one key must remove only that key -- the untouched key survives.
    iam.untag_instance_profile(InstanceProfileName=name, TagKeys=["env"])
    partial = _tagmap(iam.list_instance_profile_tags(InstanceProfileName=name)["Tags"])
    assert "env" not in partial, f"targeted key survived UntagInstanceProfile: {partial}"
    assert partial.get("team") == "payments", f"untouched key was lost: {partial}"

    iam.untag_instance_profile(InstanceProfileName=name, TagKeys=["team"])
    after = iam.list_instance_profile_tags(InstanceProfileName=name)["Tags"]
    assert after == [], f"expected tags removed after UntagInstanceProfile, got {after}"


def _tagmap(tags):
    return {t["Key"]: t["Value"] for t in tags}


def _retry_until_visible(fn, *, timeout_s=15.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code != "NoSuchEntityException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
