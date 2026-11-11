"""get-instance-profile-contract."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-instance-profile-contract"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetInstanceProfile: success-path field contract, NoSuchEntity for a name never created, and
    NoSuchEntity for a name that existed and was just deleted."""
    iam = ctx.client("iam")

    profile_name = ctx.unique_name("sim2real-gip-profile-")
    created = iam.create_instance_profile(
        InstanceProfileName=profile_name, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )

    def _cleanup():
        from botocore.exceptions import ClientError

        try:
            iam.delete_instance_profile(InstanceProfileName=profile_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)

    resp = iam.get_instance_profile(InstanceProfileName=profile_name)
    profile = resp["InstanceProfile"]
    assert profile["InstanceProfileName"] == profile_name, (
        f"expected InstanceProfileName {profile_name!r}, got {profile['InstanceProfileName']!r}"
    )
    assert profile["Arn"] == created["InstanceProfile"]["Arn"], (
        f"GetInstanceProfile Arn {profile['Arn']!r} != CreateInstanceProfile Arn "
        f"{created['InstanceProfile']['Arn']!r}"
    )
    assert profile["InstanceProfileId"] == created["InstanceProfile"]["InstanceProfileId"], (
        f"GetInstanceProfile InstanceProfileId {profile['InstanceProfileId']!r} != "
        f"CreateInstanceProfile InstanceProfileId {created['InstanceProfile']['InstanceProfileId']!r}"
    )
    assert profile["Roles"] == [], f"expected no roles on a freshly created profile, got {profile['Roles']!r}"

    never = ctx.unique_name("sim2real-nope-")
    code, message = _error(lambda: iam.get_instance_profile(InstanceProfileName=never))
    assert code == "NoSuchEntity", f"expected NoSuchEntity for a name never created, got {code}"
    expected = f"Instance Profile {never} cannot be found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    iam.delete_instance_profile(InstanceProfileName=profile_name)
    code_after_delete, message_after_delete = _error(
        lambda: iam.get_instance_profile(InstanceProfileName=profile_name)
    )
    assert code_after_delete == "NoSuchEntity", (
        f"expected NoSuchEntity for a just-deleted profile, got {code_after_delete}"
    )
    expected = f"Instance Profile {profile_name} cannot be found."
    assert message_after_delete == expected, (
        f"expected message {expected!r}, got {message_after_delete!r}"
    )


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, because an emulator
    accepting a lookup real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
