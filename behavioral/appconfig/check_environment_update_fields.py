"""environment-update-fields."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "environment-update-fields"
GROUP = 'environment'
SERVICES = ['appconfig']

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-environment-update-fields"}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateEnvironment fields are independent: a field omitted from the request is left
    untouched rather than cleared -- Description and Name each survive an update that only
    names the other, visible via an independent GetEnvironment.
    """
    ac = ctx.client("appconfig")
    app_id = ac.create_application(Name=ctx.unique_name("sim2real-behav-app-"), Tags=_TAGS)["Id"]
    ctx.on_cleanup(lambda: _safe_delete_application(ac, app_id))

    name1 = ctx.unique_name("sim2real-behav-env-")
    env_id = ac.create_environment(
        ApplicationId=app_id, Name=name1, Description="original", Tags=_TAGS
    )["Id"]
    ctx.on_cleanup(lambda: _safe_delete_environment(ac, app_id, env_id))

    baseline = ac.get_environment(ApplicationId=app_id, EnvironmentId=env_id)
    assert baseline["Name"] == name1, f"expected Name {name1!r}, got {baseline['Name']!r}"
    assert baseline["Description"] == "original", (
        f"expected Description 'original', got {baseline['Description']!r}"
    )

    # Update Description alone -- Name must survive untouched.
    after_desc = ac.update_environment(
        ApplicationId=app_id, EnvironmentId=env_id, Description="env-updated"
    )
    assert after_desc["Description"] == "env-updated", (
        f"expected Description 'env-updated', got {after_desc['Description']!r}"
    )
    assert after_desc["Name"] == name1, (
        f"Description-only update must not clear Name: expected {name1!r}, got {after_desc['Name']!r}"
    )
    got1 = ac.get_environment(ApplicationId=app_id, EnvironmentId=env_id)
    assert got1["Description"] == "env-updated", (
        f"expected Description 'env-updated', got {got1['Description']!r}"
    )
    assert got1["Name"] == name1, (
        f"expected Name to persist as {name1!r}, got {got1['Name']!r}"
    )

    # Update Name alone -- Description must survive untouched.
    name2 = ctx.unique_name("sim2real-behav-env-renamed-")
    after_name = ac.update_environment(ApplicationId=app_id, EnvironmentId=env_id, Name=name2)
    assert after_name["Name"] == name2, f"expected Name {name2!r}, got {after_name['Name']!r}"
    assert after_name["Description"] == "env-updated", (
        "Name-only update must not clear Description: expected 'env-updated', got "
        f"{after_name['Description']!r}"
    )
    got2 = ac.get_environment(ApplicationId=app_id, EnvironmentId=env_id)
    assert got2["Name"] == name2, f"expected Name {name2!r}, got {got2['Name']!r}"
    assert got2["Description"] == "env-updated", (
        f"expected Description to persist as 'env-updated', got {got2['Description']!r}"
    )


def _safe_delete_application(appconfig, app_id):
    try:
        appconfig.delete_application(ApplicationId=app_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_environment(appconfig, app_id, env_id):
    try:
        appconfig.delete_environment(ApplicationId=app_id, EnvironmentId=env_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
