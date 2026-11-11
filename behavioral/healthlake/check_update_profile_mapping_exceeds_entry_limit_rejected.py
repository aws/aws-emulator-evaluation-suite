"""update-profile-mapping-exceeds-entry-limit-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-profile-mapping-exceeds-entry-limit-rejected"
GROUP = "overly-permissive"
SERVICES = ["healthlake"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateDataTransformationProfile rejects a ProfileMapping with more than 500 entries; the draft keeps its prior content."""
    healthlake = ctx.client("healthlake")
    name = ctx.unique_name("sim2real-profile-")

    original_mapping = {"Resources/Patient.vm": "original-content"}
    created = healthlake.create_data_transformation_profile(
        SourceFormat="CCDA",
        ProfileName=name,
        Source={"ProfileMapping": {"ProfileMapping": original_mapping}},
        Tags={"sim2real": CHECK},
    )
    profile_id = created["ProfileId"]
    ctx.on_cleanup(lambda: healthlake.delete_data_transformation_profile(ProfileId=profile_id))

    too_many_entries = {f"Resources/File{i}.vm": "x" for i in range(501)}
    code, message = _error_code_and_message(
        lambda: healthlake.update_data_transformation_profile(
            ProfileId=profile_id, ProfileMapping=too_many_entries
        )
    )
    assert code == "ValidationException", (
        f"expected ValidationException for a 501-entry ProfileMapping (max 500), got {code!r}"
    )
    expected_message = (
        "1 validation error detected: Value at 'profileMapping' failed to satisfy constraint: "
        "Member must have length less than or equal to 500"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absence: the draft still holds the original mapping, not the rejected one.
    draft = healthlake.get_data_transformation_profile(ProfileId=profile_id)
    assert draft["ProfileMapping"] == original_mapping, (
        f"expected the rejected update to leave the draft mapping unchanged at {original_mapping!r}, "
        f"got {draft['ProfileMapping']!r}"
    )

    # positive control: a mapping within the limit is accepted and persists.
    valid_mapping = {"Resources/Patient.vm": "updated-content", "Resources/Encounter.vm": "enc"}
    healthlake.update_data_transformation_profile(ProfileId=profile_id, ProfileMapping=valid_mapping)
    updated_draft = healthlake.get_data_transformation_profile(ProfileId=profile_id)
    assert updated_draft["ProfileMapping"] == valid_mapping, (
        f"expected a within-limit update to persist as {valid_mapping!r}, "
        f"got {updated_draft['ProfileMapping']!r}"
    )


def _error_code_and_message(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises, because
    an emulator ACCEPTING a 501-entry mapping real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects a 501-entry ProfileMapping, but the call SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
