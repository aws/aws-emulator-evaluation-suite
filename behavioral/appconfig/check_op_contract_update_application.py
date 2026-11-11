"""op-contract-updateApplication."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-updateApplication"
GROUP = "error-semantics"
SERVICES = ["appconfig"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateApplication persists the new Name/Description, visible via
    GetApplication; updating a nonexistent ApplicationId yields
    ResourceNotFoundException."""
    appconfig = ctx.client("appconfig")

    orig_name = ctx.unique_name("sim2real-behav-app-")
    app_id = appconfig.create_application(Name=orig_name, Description="original")["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))

    new_name = ctx.unique_name("sim2real-behav-app-renamed-")
    updated = appconfig.update_application(
        ApplicationId=app_id, Name=new_name, Description="updated-description"
    )
    assert updated["Id"] == app_id, f"expected {app_id}, got {updated['Id']}"
    assert updated["Name"] == new_name, f"expected {new_name}, got {updated['Name']}"
    assert updated["Description"] == "updated-description", (
        f"expected 'updated-description', got {updated['Description']!r}"
    )

    fetched = appconfig.get_application(ApplicationId=app_id)
    assert fetched["Name"] == new_name, "GetApplication must reflect the update"
    assert fetched["Description"] == "updated-description", (
        f"expected 'updated-description', got {fetched['Description']!r}"
    )

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    err = _error(lambda: appconfig.update_application(ApplicationId="0000000", Name="whatever"))
    assert err["Code"] == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {err}"
    expected_message = f"Application with Id 0000000 could not be found for account {account_id}."
    assert err["Message"] == expected_message, f"expected message {expected_message!r}, got {err['Message']!r}"


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
