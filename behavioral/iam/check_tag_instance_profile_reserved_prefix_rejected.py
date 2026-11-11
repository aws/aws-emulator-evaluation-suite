"""tag-instance-profile-reserved-prefix-rejected."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "tag-instance-profile-reserved-prefix-rejected"
GROUP = "overly-permissive"
SERVICES = ["iam"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagInstanceProfile rejects a tag key using the AWS-reserved 'aws:'
    prefix with an InvalidInput error code, applies no tag, while a normal
    tag key on the same profile succeeds (positive control)."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-ip-reserved-")
    iam.create_instance_profile(InstanceProfileName=name)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=name))

    # Break the precondition: tag key uses the reserved "aws:" prefix.
    bad_tags = [{"Key": "aws:reserved-marker", "Value": "should-not-apply"}]
    code, message = _error(lambda: iam.tag_instance_profile(InstanceProfileName=name, Tags=bad_tags))
    assert code == "InvalidInput", f"expected InvalidInput, got {code}"
    expected = "Tag keys beginning with aws: are reserved for system use."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the reserved-prefix tag was not applied.
    after_reject = iam.list_instance_profile_tags(InstanceProfileName=name)["Tags"]
    assert after_reject == [], (
        f"expected no tags applied after rejected TagInstanceProfile, got {after_reject}"
    )

    # Positive control: a normal tag key on the same profile succeeds.
    good_tags = [{"Key": "env", "Value": "test"}]
    iam.tag_instance_profile(InstanceProfileName=name, Tags=good_tags)
    listed = iam.list_instance_profile_tags(InstanceProfileName=name)["Tags"]
    assert {(t["Key"], t["Value"]) for t in listed} == {(t["Key"], t["Value"]) for t in good_tags}, (
        f"expected tag {good_tags} to apply, got {listed}"
    )


def _error(fn: Any) -> tuple[str, str]:
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises, because an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects a tag key with the 'aws:' prefix, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
