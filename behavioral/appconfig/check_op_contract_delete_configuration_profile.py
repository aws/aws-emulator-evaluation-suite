"""op-contract-deleteConfigurationProfile."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deleteConfigurationProfile"
GROUP = "error-semantics"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-delete-configuration-profile-rejected"}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteConfigurationProfile removes the profile (positive control); calling it a
    second time on the now-absent profile is rejected with ResourceNotFoundException and
    the profile stays absent."""
    appconfig = ctx.client("appconfig")

    app_id = appconfig.create_application(Name=ctx.unique_name("sim2real-app-"), Tags=_TAGS)["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))

    profile_id = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-cp-"),
        LocationUri="hosted",
        Tags=_TAGS,
    )["Id"]

    # positive control: the profile exists before deletion
    before = appconfig.list_configuration_profiles(ApplicationId=app_id)["Items"]
    before_ids = [p["Id"] for p in before]
    assert profile_id in before_ids, f"expected {profile_id} listed before delete, got {before_ids}"

    appconfig.delete_configuration_profile(ApplicationId=app_id, ConfigurationProfileId=profile_id)

    after = appconfig.list_configuration_profiles(ApplicationId=app_id)["Items"]
    after_ids = [p["Id"] for p in after]
    assert profile_id not in after_ids, f"expected {profile_id} absent after delete, got {after_ids}"
    account = ctx.client("sts").get_caller_identity()["Account"]
    not_found = (
        f"Configuration Profile with Application Id {app_id} and Configuration Profile Id "
        f"{profile_id} could not be found for account {account}."
    )
    code, message = _error(
        lambda: appconfig.get_configuration_profile(
            ApplicationId=app_id, ConfigurationProfileId=profile_id
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == not_found, f"expected message {not_found!r}, got {message!r}"

    # negative: deleting the already-deleted profile is rejected, effect stays absent
    code, message = _error(
        lambda: appconfig.delete_configuration_profile(
            ApplicationId=app_id, ConfigurationProfileId=profile_id
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == not_found, f"expected message {not_found!r}, got {message!r}"
    after2_ids = [p["Id"] for p in appconfig.list_configuration_profiles(ApplicationId=app_id)["Items"]]
    assert profile_id not in after2_ids, f"expected {profile_id} absent after re-delete, got {after2_ids}"


def _error(fn):
    """Call fn(); return its botocore (error code, error message). An unexpected SUCCESS raises, because a
    target that accepts a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
