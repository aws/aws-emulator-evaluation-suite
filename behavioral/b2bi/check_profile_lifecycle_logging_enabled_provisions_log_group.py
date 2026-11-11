"""profile-lifecycle-logging-enabled-provisions-log-group."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "profile-lifecycle-logging-enabled-provisions-log-group"
GROUP = "lifecycle"
SERVICES = ["b2bi"]


def _delete_profile_if_present(b2bi, profile_id: str) -> None:
    try:
        b2bi.delete_profile(profileId=profile_id)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error(fn) -> tuple[str, str]:
    """Call fn(), which AWS refuses; return the ClientError's (code, message). An unexpected
    success raises, so a target that accepts the call fails loudly instead of mismatching."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateProfile with logging=ENABLED provisions a real CloudWatch log group, and
    GetProfile/ListProfiles consistently report it; deleting the profile removes it from
    ListProfiles."""
    b2bi = ctx.client("b2bi")
    logs = ctx.client("logs")
    name = ctx.unique_name("sim2real-b2bi-profile-")

    created = b2bi.create_profile(
        name=name,
        phone="+14155550100",
        businessName=f"{name}-biz",
        logging="ENABLED",
        tags=[{"Key": "Environment", "Value": "sim2real-test"}],
    )
    profile_id = created["profileId"]
    ctx.on_cleanup(lambda: _delete_profile_if_present(b2bi, profile_id))

    log_group_name = created.get("logGroupName")
    assert log_group_name, "CreateProfile response with logging=ENABLED must include logGroupName"

    fetched = b2bi.get_profile(profileId=profile_id)
    assert fetched["logGroupName"] == log_group_name, (
        f"expected GetProfile logGroupName {log_group_name!r}, got {fetched.get('logGroupName')!r}"
    )
    assert fetched["logging"] == "ENABLED", f"expected logging ENABLED, got {fetched['logging']!r}"

    groups = logs.describe_log_groups(logGroupNamePrefix=log_group_name)["logGroups"]
    assert any(g["logGroupName"] == log_group_name for g in groups), (
        f"expected a real CloudWatch log group named {log_group_name!r}"
    )

    listed_ids = {p["profileId"] for p in b2bi.list_profiles(maxResults=100).get("profiles", [])}
    assert profile_id in listed_ids, f"expected {profile_id!r} in ListProfiles, got {listed_ids!r}"

    b2bi.delete_profile(profileId=profile_id)

    code, message = _error(lambda: b2bi.get_profile(profileId=profile_id))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for GetProfile on deleted profile, got {code!r}"
    )
    expected = f"Profile ID {profile_id} not found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    listed_ids_after = {p["profileId"] for p in b2bi.list_profiles(maxResults=100).get("profiles", [])}
    assert profile_id not in listed_ids_after, (
        f"expected {profile_id!r} absent from ListProfiles after delete, still present in {listed_ids_after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
