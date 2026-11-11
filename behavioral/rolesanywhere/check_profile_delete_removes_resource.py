"""profile-delete-removes-resource."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "profile-delete-removes-resource"
GROUP = "state"
SERVICES = ["rolesanywhere"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteProfile is irreversible: GetProfile 404s, the profile vanishes from ListProfiles, and a
    mutation on the dead id also fails not-found."""
    ra = ctx.client("rolesanywhere")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    role_arn = f"arn:aws:iam::{account_id}:role/{ctx.unique_name('sim2real-ra-role-')}"

    created = ra.create_profile(
        name=ctx.unique_name("sim2real-ra-profile-"),
        roleArns=[role_arn],
        tags=[{"key": "sim2real", "value": "profile-delete-removes-resource"}],
    )["profile"]
    profile_id = created["profileId"]
    ctx.on_cleanup(lambda: _delete_profile_ignore_missing(ra, profile_id))

    # Sanity: it exists before deletion.
    ra.get_profile(profileId=profile_id)
    assert _profile_id_in_list(ra, profile_id), f"expected {profile_id} in ListProfiles before delete, was absent"

    ra.delete_profile(profileId=profile_id)

    expected_message = (
        f"The item doesn't exist. arn: arn:aws:rolesanywhere:{ctx.region}:{account_id}:"
        f"profile/{profile_id} ; aborting."
    )
    error = _client_error(lambda: ra.get_profile(profileId=profile_id))
    assert error["Code"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from GetProfile on a deleted id, got {error['Code']!r}"
    )
    assert error.get("Message") == expected_message, (
        f"expected GetProfile message {expected_message!r}, got {error.get('Message')!r}"
    )
    assert not _profile_id_in_list(ra, profile_id), f"expected {profile_id} absent from ListProfiles after delete, still present"

    mutation_error = _client_error(lambda: ra.enable_profile(profileId=profile_id))
    assert mutation_error["Code"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from EnableProfile on a deleted id, got {mutation_error['Code']!r}"
    )
    assert mutation_error.get("Message") == expected_message, (
        f"expected EnableProfile message {expected_message!r}, got {mutation_error.get('Message')!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore error dict. An unexpected SUCCESS raises, because a target
    accepting a call real AWS refuses must not read as an error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _profile_id_in_list(ra, profile_id: str) -> bool:
    next_token = None
    while True:
        kwargs = {"nextToken": next_token} if next_token else {}
        resp = ra.list_profiles(**kwargs)
        if any(p["profileId"] == profile_id for p in resp.get("profiles", [])):
            return True
        next_token = resp.get("nextToken")
        if not next_token:
            return False


def _delete_profile_ignore_missing(ra, profile_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        ra.delete_profile(profileId=profile_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
