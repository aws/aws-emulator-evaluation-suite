"""op-contract-listConfigurationProfiles."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-listConfigurationProfiles"
GROUP = "error-semantics"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-op-contract-list-configuration-profiles"}


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListConfigurationProfiles enumerates exactly the profiles created under the
    application with their correct Name/Type/LocationUri, and no others; listing under
    a nonexistent ApplicationId is rejected with ResourceNotFoundException."""
    appconfig = ctx.client("appconfig")

    app_id = appconfig.create_application(Name=ctx.unique_name("sim2real-app-"), Tags=_TAGS)["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))

    name_a = ctx.unique_name("sim2real-cp-a-")
    profile_a = appconfig.create_configuration_profile(
        ApplicationId=app_id, Name=name_a, LocationUri="hosted", Tags=_TAGS
    )["Id"]
    ctx.on_cleanup(
        lambda: appconfig.delete_configuration_profile(
            ApplicationId=app_id, ConfigurationProfileId=profile_a
        )
    )

    name_b = ctx.unique_name("sim2real-cp-b-")
    profile_b = appconfig.create_configuration_profile(
        ApplicationId=app_id, Name=name_b, LocationUri="hosted", Type="AWS.Freeform", Tags=_TAGS
    )["Id"]
    ctx.on_cleanup(
        lambda: appconfig.delete_configuration_profile(
            ApplicationId=app_id, ConfigurationProfileId=profile_b
        )
    )

    items = appconfig.list_configuration_profiles(ApplicationId=app_id)["Items"]
    by_id = {i["Id"]: i for i in items}
    assert set(by_id) == {profile_a, profile_b}, f"unexpected item set: {by_id.keys()}"
    assert by_id[profile_a]["Name"] == name_a, f"expected Name {name_a!r}, got {by_id[profile_a]['Name']!r}"
    assert by_id[profile_a]["LocationUri"] == "hosted", (
        f"expected LocationUri 'hosted', got {by_id[profile_a]['LocationUri']!r}"
    )
    assert by_id[profile_b]["Name"] == name_b, f"expected Name {name_b!r}, got {by_id[profile_b]['Name']!r}"
    assert by_id[profile_b]["Type"] == "AWS.Freeform", (
        f"expected Type 'AWS.Freeform', got {by_id[profile_b]['Type']!r}"
    )

    # error boundary: ApplicationId never existed
    err = _error(
        lambda: appconfig.list_configuration_profiles(ApplicationId="00000000")
    )
    assert err["Code"] == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {err['Code']}"
    account = ctx.client("sts").get_caller_identity()["Account"]
    assert err["Message"] == f"Application with Id 00000000 could not be found for account {account}.", (
        f"unexpected message: {err['Message']!r}"
    )


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because a target
    ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
