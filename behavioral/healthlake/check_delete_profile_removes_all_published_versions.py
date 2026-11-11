"""delete-profile-removes-all-published-versions."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-profile-removes-all-published-versions"
GROUP = "state"
SERVICES = ["healthlake"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Deleting a data transformation profile removes the DRAFT and every published version."""
    healthlake = ctx.client("healthlake")
    name = ctx.unique_name("sim2real-profile-")

    created = healthlake.create_data_transformation_profile(
        SourceFormat="CCDA",
        ProfileName=name,
        Source={"ProfileMapping": {"ProfileMapping": {"Resources/Patient.vm": "v1-content"}}},
    )
    profile_id = created["ProfileId"]

    def _cleanup():
        try:
            healthlake.delete_data_transformation_profile(ProfileId=profile_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    healthlake.publish_data_transformation_profile(ProfileId=profile_id, SourceFormat="CCDA")
    healthlake.publish_data_transformation_profile(ProfileId=profile_id, SourceFormat="CCDA")

    versions = _poll_for_versions(healthlake, profile_id, {1, 2})
    published_version_numbers = {item["Version"] for item in versions}
    assert {1, 2}.issubset(published_version_numbers), (
        f"expected versions 1 and 2 to be listed as published, got {published_version_numbers}"
    )

    healthlake.delete_data_transformation_profile(ProfileId=profile_id)

    code, message = _error_code_and_message(
        lambda: healthlake.get_data_transformation_profile(ProfileId=profile_id)
    )
    assert code == "ResourceNotFoundException", (
        f"expected the deleted profile {profile_id!r} to read back as ResourceNotFoundException, "
        f"got {code!r}"
    )
    expected = f"Profile '{profile_id}' not found"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    for version in (1, 2):
        code, message = _error_code_and_message(
            lambda v=version: healthlake.get_data_transformation_profile(
                ProfileId=profile_id, ProfileVersion=v
            )
        )
        assert code == "ResourceNotFoundException", (
            f"expected published version {version} to be gone after the profile delete, "
            f"got {code!r}"
        )
        expected = f"Profile '{profile_id}' version {version} not found"
        assert message == expected, f"expected message {expected!r}, got {message!r}"

    code, message = _error_code_and_message(
        lambda: healthlake.publish_data_transformation_profile(ProfileId=profile_id, SourceFormat="CCDA")
    )
    assert code == "ResourceNotFoundException", (
        f"expected publishing against the deleted profile {profile_id!r} to be rejected, got {code!r}"
    )
    # Real AWS names the DRAFT (version 0) as the missing source of the publish.
    expected = f"Profile '{profile_id}' version 0 not found"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    code, message = _error_code_and_message(
        lambda: healthlake.list_data_transformation_profile_versions(ProfileId=profile_id)
    )
    assert code == "ResourceNotFoundException", (
        f"expected listing versions of the deleted profile {profile_id!r} to be rejected, "
        f"got {code!r}"
    )
    expected = f"Profile '{profile_id}' not found"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _poll_for_versions(healthlake, profile_id, expected_version_numbers, *, timeout_s=30.0, interval_s=2.0):
    import time

    deadline = time.monotonic() + timeout_s
    last_items = []
    while time.monotonic() < deadline:
        page = healthlake.list_data_transformation_profile_versions(ProfileId=profile_id)
        last_items = page["Items"]
        seen = {item["Version"] for item in last_items}
        if expected_version_numbers.issubset(seen):
            return last_items
        time.sleep(interval_s)
    return last_items


def _error_code_and_message(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
