"""create-configuration-profile-requires-valid-application."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-configuration-profile-requires-valid-application"
GROUP = 'configuration-profile'
SERVICES = ['appconfig']


def _error(fn):
    """Call fn() and return its (error code, error message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateConfigurationProfile on a nonexistent ApplicationId fails with
    ResourceNotFoundException, while the identical call on a real application succeeds."""
    ac = ctx.client("appconfig")
    app_id = ac.create_application(Name=ctx.unique_name("sim2real-behav-app-"))["Id"]
    ctx.on_cleanup(lambda: ac.delete_application(ApplicationId=app_id))

    control = ac.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-behav-cp-"),
        LocationUri="hosted",
    )
    assert control["Id"], f"positive control did not return an Id: {control!r}"
    # Registered after the application, so it runs first: AppConfig refuses DeleteApplication
    # while a configuration profile survives under it.
    ctx.on_cleanup(
        lambda: ac.delete_configuration_profile(
            ApplicationId=app_id, ConfigurationProfileId=control["Id"]
        )
    )

    # AppConfig ids are 7 characters; truncate a unique name so the id is
    # well-formed but refers to nothing.
    bogus_app_id = ctx.unique_name("bogus")[:7]

    code, message = _error(
        lambda: ac.create_configuration_profile(
            ApplicationId=bogus_app_id,
            Name=ctx.unique_name("sim2real-behav-cp-"),
            LocationUri="hosted",
        )
    )
    assert code == "ResourceNotFoundException", code
    account = ctx.client("sts").get_caller_identity()["Account"]
    expected = f"Application with Id {bogus_app_id} could not be found for account {account}."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
