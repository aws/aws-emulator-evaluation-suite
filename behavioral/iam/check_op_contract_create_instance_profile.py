"""op-contract-create-instance-profile."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-create-instance-profile"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateInstanceProfile: success-path returns a profile created with an empty Roles
    list and default Path; error boundary is EntityAlreadyExistsException for a duplicate
    InstanceProfileName."""
    iam = ctx.client("iam")

    profile_name = ctx.unique_name("sim2real-ip-")
    created = iam.create_instance_profile(InstanceProfileName=profile_name)["InstanceProfile"]
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name))

    assert created["InstanceProfileName"] == profile_name, (
        f"CreateInstanceProfile echoed InstanceProfileName={created['InstanceProfileName']!r}, "
        f"expected {profile_name!r}"
    )
    assert created["Path"] == "/", f"expected default Path '/', got {created['Path']!r}"
    assert created["Roles"] == [], f"a freshly created instance profile must have no roles, got {created['Roles']!r}"
    assert created["Arn"].endswith(f":instance-profile/{profile_name}"), (
        f"Arn {created['Arn']!r} does not end with :instance-profile/{profile_name}"
    )

    fetched = iam.get_instance_profile(InstanceProfileName=profile_name)["InstanceProfile"]
    assert fetched["InstanceProfileId"] == created["InstanceProfileId"], (
        f"GetInstanceProfile id {fetched['InstanceProfileId']!r} != "
        f"CreateInstanceProfile id {created['InstanceProfileId']!r}"
    )
    assert fetched["Roles"] == [], f"GetInstanceProfile Roles should be empty, got {fetched['Roles']!r}"

    # A different Path on the duplicate attempt: an upsert-style emulator that accepts the
    # duplicate as a silent update would leak through here even though the id equality check
    # above cannot detect it (the id never changes on an in-place update).
    code, message = _error(
        lambda: iam.create_instance_profile(InstanceProfileName=profile_name, Path="/should-not-apply/")
    )
    assert code == "EntityAlreadyExists", f"expected EntityAlreadyExists for duplicate InstanceProfileName, got {code}"
    expected = f"Instance Profile {profile_name} already exists."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    unaffected = iam.get_instance_profile(InstanceProfileName=profile_name)["InstanceProfile"]
    assert unaffected["InstanceProfileId"] == created["InstanceProfileId"], (
        f"rejected duplicate create must not replace the original: id was "
        f"{created['InstanceProfileId']!r}, now {unaffected['InstanceProfileId']!r}"
    )
    assert unaffected["Path"] == "/", (
        f"rejected duplicate create (Path='/should-not-apply/') must not change the original's "
        f"path: now {unaffected['Path']!r}"
    )


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
