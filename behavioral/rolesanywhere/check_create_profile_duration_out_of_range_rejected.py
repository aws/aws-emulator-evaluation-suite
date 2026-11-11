"""create-profile-duration-out-of-range-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-profile-duration-out-of-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["rolesanywhere"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateProfile with durationSeconds above the 43200 s maximum is refused with
    ValidationException and creates no profile, while the same call with a valid duration succeeds
    and GetProfile reads it back.
    """
    ra = ctx.client("rolesanywhere")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    role_arn = f"arn:aws:iam::{account_id}:role/{ctx.unique_name('sim2real-ra-role-')}"
    rejected_name = ctx.unique_name("sim2real-ra-baddur-")

    error = _rejects(
        ra, lambda: ra.create_profile(name=rejected_name, roleArns=[role_arn], durationSeconds=43201)
    )
    assert error["Code"] == "ValidationException", (
        f"durationSeconds=43201 (above the 43200 max) was rejected with "
        f"{error['Code']!r}, expected 'ValidationException'"
    )
    expected_message = (
        "1 validation error detected: Value '43201' at 'durationSeconds' failed to satisfy "
        "constraint: Member must have value less than or equal to 43200"
    )
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )
    assert not _profile_name_in_list(ra, rejected_name), (
        f"CreateProfile was rejected but {rejected_name!r} is visible in ListProfiles"
    )

    # Positive control: same shape, in-range duration, succeeds.
    accepted_name = ctx.unique_name("sim2real-ra-gooddur-")
    created = ra.create_profile(name=accepted_name, roleArns=[role_arn], durationSeconds=43200)["profile"]
    profile_id = created["profileId"]
    ctx.on_cleanup(lambda: ra.delete_profile(profileId=profile_id))
    assert created["durationSeconds"] == 43200, (
        f"CreateProfile with durationSeconds=43200 (the max) returned "
        f"{created['durationSeconds']!r} in its own response, expected 43200"
    )

    # Independent read, through a different operation than the one that mutated.
    got = ra.get_profile(profileId=profile_id)["profile"]
    assert got["durationSeconds"] == 43200, (
        f"GetProfile on the accepted profile reports durationSeconds="
        f"{got['durationSeconds']!r}, expected 43200 to match what CreateProfile returned"
    )


def _rejects(ra, fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS deletes the profile it
    created (so an over-permissive target does not leak it) and raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    profile_id = result["profile"]["profileId"]
    ra.delete_profile(profileId=profile_id)
    raise AssertionError(
        f"real AWS rejects durationSeconds=43201 with ValidationException, but the call "
        f"SUCCEEDED and created profile {profile_id!r} (now deleted)"
    )


def _profile_name_in_list(ra, name: str) -> bool:
    next_token = None
    while True:
        kwargs = {"nextToken": next_token} if next_token else {}
        resp = ra.list_profiles(**kwargs)
        if any(p["name"] == name for p in resp.get("profiles", [])):
            return True
        next_token = resp.get("nextToken")
        if not next_token:
            return False


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
