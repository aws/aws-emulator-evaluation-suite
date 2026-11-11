"""get-profile-out-of-range-version-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-profile-out-of-range-version-not-found"
GROUP = "error-semantics"
SERVICES = ["healthlake"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetDataTransformationProfile with a ProfileVersion that was never published raises ResourceNotFoundException, while the existing version still reads fine."""
    healthlake = ctx.client("healthlake")
    name = ctx.unique_name("sim2real-profile-")

    created = healthlake.create_data_transformation_profile(
        SourceFormat="CCDA",
        ProfileName=name,
        Source={"ProfileMapping": {"ProfileMapping": {"Resources/Patient.vm": "content"}}},
        Tags={"sim2real": CHECK},
    )
    profile_id = created["ProfileId"]
    ctx.on_cleanup(lambda: healthlake.delete_data_transformation_profile(ProfileId=profile_id))

    healthlake.publish_data_transformation_profile(ProfileId=profile_id, SourceFormat="CCDA")

    baseline_versions = _poll_for_version(healthlake, profile_id, 1)
    baseline_count = len(baseline_versions)
    assert baseline_count >= 1, f"expected version 1 to be listed after publish, got {baseline_versions}"

    code, message = _error_code_and_message(
        lambda: healthlake.get_data_transformation_profile(ProfileId=profile_id, ProfileVersion=5)
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for out-of-range ProfileVersion=5, got {code!r}"
    )
    expected_message = f"Profile '{profile_id}' version 5 not found"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absence: the out-of-range lookup did not create/alter any version -- the
    # published-version count observed right after publish must be unchanged now.
    after_lookup = healthlake.list_data_transformation_profile_versions(ProfileId=profile_id)["Items"]
    assert len(after_lookup) == baseline_count, (
        f"expected version count unchanged by the failed lookup, got {len(after_lookup)} "
        f"vs baseline {baseline_count}"
    )

    # positive control: the version that really exists still reads correctly.
    real_version = healthlake.get_data_transformation_profile(ProfileId=profile_id, ProfileVersion=1)
    assert real_version["Version"] == 1, f"expected version 1 to still read back, got {real_version!r}"


def _poll_for_version(healthlake, profile_id, version_number, *, timeout_s=30.0, interval_s=2.0):
    import time

    deadline = time.monotonic() + timeout_s
    last_items = []
    while time.monotonic() < deadline:
        page = healthlake.list_data_transformation_profile_versions(ProfileId=profile_id)
        last_items = page["Items"]
        if any(item["Version"] == version_number for item in last_items):
            return last_items
        time.sleep(interval_s)
    raise AssertionError(
        f"version {version_number} not observed within {timeout_s}s; last saw {last_items!r}"
    )


def _error_code_and_message(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
