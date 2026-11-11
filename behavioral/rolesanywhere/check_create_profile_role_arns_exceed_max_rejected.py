"""create-profile-role-arns-exceed-max-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-profile-role-arns-exceed-max-rejected"
GROUP = "overly-permissive"
SERVICES = ["rolesanywhere"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateProfile rejects a roleArns list longer than the documented 250-entry
    quota with ValidationException, creates no profile, and the same call shape
    with a single role ARN succeeds (positive control)."""
    ra = ctx.client("rolesanywhere")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    too_many_roles = [
        f"arn:aws:iam::{account_id}:role/sim2real-ra-quota-role-{i}" for i in range(251)
    ]
    rejected_name = ctx.unique_name("sim2real-ra-toomanyroles-")

    error = _client_error(lambda: ra.create_profile(name=rejected_name, roleArns=too_many_roles))
    assert error["Code"] == "ValidationException", f"expected ValidationException, got {error['Code']!r}"
    expected_message = (
        f"1 validation error detected: Value '[{', '.join(too_many_roles)}]' at 'roleArns' failed "
        "to satisfy constraint: Member must have length less than or equal to 250"
    )
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )
    assert not _profile_name_in_list(ra, rejected_name), (
        f"profile {rejected_name!r} should not exist after a rejected CreateProfile, but "
        "ListProfiles shows it"
    )

    # Positive control: same shape, single role ARN, succeeds.
    accepted_name = ctx.unique_name("sim2real-ra-onerole-")
    created = ra.create_profile(
        name=accepted_name, roleArns=[f"arn:aws:iam::{account_id}:role/sim2real-ra-quota-role-0"]
    )["profile"]
    profile_id = created["profileId"]
    ctx.on_cleanup(lambda: ra.delete_profile(profileId=profile_id))
    assert len(created["roleArns"]) == 1, (
        f"expected 1 roleArn on the positive control, got {created['roleArns']!r}"
    )

    # Independent read at the destination: GetProfile must reflect the same
    # roleArns the create call returned, not just echo the mutating response.
    got = ra.get_profile(profileId=profile_id)["profile"]
    assert got["roleArns"] == created["roleArns"], (
        f"expected GetProfile roleArns {created['roleArns']!r}, got {got['roleArns']!r}"
    )


def _client_error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(
        f"expected ValidationException, but the call SUCCEEDED and returned {result!r}"
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
