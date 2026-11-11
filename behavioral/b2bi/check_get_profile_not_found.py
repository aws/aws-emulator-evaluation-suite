"""get-profile-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-profile-not-found"
GROUP = "error-semantics"
SERVICES = ["b2bi"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetProfile on a nonexistent profileId returns ResourceNotFoundException while a real profile
    is fetched; after deleting it, both a read and a mutation of its id return the same error."""
    b2bi = ctx.client("b2bi")

    code, message = _error(lambda: b2bi.get_profile(profileId="profile-doesnotexist000000"))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected = "Profile ID profile-doesnotexist000000 not found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    name = ctx.unique_name("sim2real-b2bi-profile-")
    resp = b2bi.create_profile(
        name=name,
        phone="+15555550100",
        businessName=ctx.unique_name("sim2real-b2bi-biz-"),
        logging="DISABLED",
    )
    profile_id = resp["profileId"]
    ctx.on_cleanup(lambda: _delete_profile_if_present(b2bi, profile_id))

    described = b2bi.get_profile(profileId=profile_id)
    assert described["name"] == name
    assert described["profileId"] == profile_id

    b2bi.delete_profile(profileId=profile_id)

    gone_code, message = _error(lambda: b2bi.get_profile(profileId=profile_id))
    assert gone_code == "ResourceNotFoundException", (
        f"a deleted profile must genuinely not exist, got {gone_code!r}"
    )
    expected = f"Profile ID {profile_id} not found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    mutate_code, message = _error(lambda: b2bi.update_profile(profileId=profile_id, name="renamed"))
    assert mutate_code == "ResourceNotFoundException", (
        f"a mutation on a deleted profile must also be rejected as not-found, got {mutate_code!r}"
    )
    expected = f"Profile with profileId {profile_id} not found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn) -> tuple[str, str]:
    """Call fn(), which AWS refuses; return the ClientError's (code, message). An unexpected
    success raises, so accepting a request AWS refuses fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


def _delete_profile_if_present(b2bi, profile_id):
    from botocore.exceptions import ClientError

    try:
        b2bi.delete_profile(profileId=profile_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
