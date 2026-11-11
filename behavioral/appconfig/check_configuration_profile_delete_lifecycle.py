"""configuration-profile-delete-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "configuration-profile-delete-lifecycle"
GROUP = 'configuration-profile'
SERVICES = ['appconfig']

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-configuration-profile-delete-lifecycle"}


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of its ClientError. An unexpected SUCCESS
    raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to fail, but it SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Deleted configuration profile disappears from Get and List, and a subsequent
    mutation against the dead id is rejected rather than silently accepted."""
    ac = ctx.client("appconfig")
    app_id = ac.create_application(Name=ctx.unique_name("sim2real-behav-app-"), Tags=_TAGS)["Id"]
    ctx.on_cleanup(lambda: ac.delete_application(ApplicationId=app_id))
    profile = ac.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-behav-cp-"),
        LocationUri="hosted",
        Tags=_TAGS,
    )
    profile_id = profile["Id"]

    listed = ac.list_configuration_profiles(ApplicationId=app_id)
    assert any(item["Id"] == profile_id for item in listed["Items"]), (
        f"expected {profile_id} in freshly-created list, got {[i['Id'] for i in listed['Items']]}"
    )

    ac.delete_configuration_profile(ApplicationId=app_id, ConfigurationProfileId=profile_id)

    account = ctx.client("sts").get_caller_identity()["Account"]
    not_found = (
        f"Configuration Profile with Application Id {app_id} and Configuration Profile Id "
        f"{profile_id} could not be found for account {account}."
    )
    get_code, get_message = _error(
        lambda: ac.get_configuration_profile(ApplicationId=app_id, ConfigurationProfileId=profile_id)
    )
    assert get_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from Get on a deleted profile, got {get_code}"
    )
    assert get_message == not_found, f"expected message {not_found!r}, got {get_message!r}"
    listed_after = ac.list_configuration_profiles(ApplicationId=app_id)
    assert all(item["Id"] != profile_id for item in listed_after["Items"]), (
        f"deleted profile {profile_id} still present in list: {[i['Id'] for i in listed_after['Items']]}"
    )

    update_code, update_message = _error(
        lambda: ac.update_configuration_profile(
            ApplicationId=app_id, ConfigurationProfileId=profile_id, Name="post-delete-mutation"
        )
    )
    assert update_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException mutating a deleted profile, got {update_code}"
    )
    assert update_message == not_found, f"expected message {not_found!r}, got {update_message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
