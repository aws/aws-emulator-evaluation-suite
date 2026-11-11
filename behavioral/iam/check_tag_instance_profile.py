"""tag-instance-profile."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-instance-profile"
GROUP = 'tags'
SERVICES = ['iam']


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagInstanceProfile persists tags that GetInstanceProfile / ListInstanceProfileTags then
    reflect exactly (not a fixed/empty stand-in); tagging a nonexistent InstanceProfileName is
    rejected NoSuchEntity."""
    iam = ctx.client("iam")
    name = ctx.unique_name("ip-tag-")
    iam.create_instance_profile(InstanceProfileName=name)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=name))

    iam.tag_instance_profile(InstanceProfileName=name, Tags=[{"Key": "sim2real-k", "Value": "v1"}])
    ctx.on_cleanup(lambda: iam.untag_instance_profile(InstanceProfileName=name, TagKeys=["sim2real-k"]))

    tags = iam.list_instance_profile_tags(InstanceProfileName=name)["Tags"]
    assert {"Key": "sim2real-k", "Value": "v1"} in tags, f"tag missing: {tags}"
    profile_tags = iam.get_instance_profile(InstanceProfileName=name)["InstanceProfile"].get(
        "Tags", []
    )
    assert {"Key": "sim2real-k", "Value": "v1"} in profile_tags, (
        f"GetInstanceProfile omitted the tag: {profile_tags}"
    )

    missing = ctx.unique_name("missing-")
    code, message = _error(
        lambda: iam.tag_instance_profile(
            InstanceProfileName=missing, Tags=[{"Key": "k", "Value": "v"}]
        )
    )
    assert code == "NoSuchEntity", (
        f"expected NoSuchEntity for a nonexistent InstanceProfileName, got {code}"
    )
    expected = f"Instance Profile {missing} cannot be found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
