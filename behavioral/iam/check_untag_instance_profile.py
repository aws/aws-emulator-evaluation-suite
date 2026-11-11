"""untag-instance-profile."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "untag-instance-profile"
GROUP = 'tags'
SERVICES = ['iam']


def _error(fn):
    """Call fn(); return the botocore (Code, Message) of the ClientError it raises. An unexpected
    SUCCESS raises, because an emulator ACCEPTING input real AWS refuses is the strongest signal
    available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected NoSuchEntity, but the call SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagInstanceProfile removes ONLY the named keys -- a second, untouched tag survives the call
    -- and a subsequent removal of the remaining key clears it entirely; untagging a nonexistent
    InstanceProfileName is rejected NoSuchEntity."""
    iam = ctx.client("iam")
    name = ctx.unique_name("ip-untag-")
    iam.create_instance_profile(InstanceProfileName=name)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=name))
    iam.tag_instance_profile(
        InstanceProfileName=name,
        Tags=[{"Key": "sim2real-keep", "Value": "v1"}, {"Key": "sim2real-drop", "Value": "v2"}],
    )

    iam.untag_instance_profile(InstanceProfileName=name, TagKeys=["sim2real-drop"])
    tags = iam.list_instance_profile_tags(InstanceProfileName=name)["Tags"]
    assert {"Key": "sim2real-keep", "Value": "v1"} in tags, f"untouched tag lost: {tags}"
    assert not any(t["Key"] == "sim2real-drop" for t in tags), f"targeted tag survived: {tags}"

    iam.untag_instance_profile(InstanceProfileName=name, TagKeys=["sim2real-keep"])
    tags_after = iam.list_instance_profile_tags(InstanceProfileName=name)["Tags"]
    assert tags_after == [], f"expected no tags remaining, got {tags_after}"

    missing = ctx.unique_name("missing-")
    code, message = _error(
        lambda: iam.untag_instance_profile(InstanceProfileName=missing, TagKeys=["k"])
    )
    assert code == "NoSuchEntity", (
        f"expected NoSuchEntity for a nonexistent InstanceProfileName, got {code}"
    )
    expected = f"Instance Profile {missing} cannot be found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
