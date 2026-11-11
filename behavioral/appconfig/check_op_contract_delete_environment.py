"""op-contract-deleteEnvironment."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deleteEnvironment"
GROUP = "error-semantics"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-delete-environment-rejected"}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteEnvironment removes the environment (positive control); a second delete on
    the now-absent environment is rejected with ResourceNotFoundException and the
    environment remains absent from the application's environment listing."""
    appconfig = ctx.client("appconfig")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    app_id = appconfig.create_application(Name=ctx.unique_name("sim2real-app-"), Tags=_TAGS)["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))

    env_id = appconfig.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-env-"), Tags=_TAGS
    )["Id"]

    before = appconfig.list_environments(ApplicationId=app_id)["Items"]
    assert any(e["Id"] == env_id for e in before), (
        f"expected {env_id} in freshly-created environment listing, got {before!r}"
    )

    appconfig.delete_environment(ApplicationId=app_id, EnvironmentId=env_id)

    after = appconfig.list_environments(ApplicationId=app_id)["Items"]
    assert all(e["Id"] != env_id for e in after), (
        f"expected {env_id} absent after delete, still listed in {after!r}"
    )
    not_found = (
        f"Environment with Application Id {app_id} and Environment Id {env_id} "
        f"could not be found for account {account_id}."
    )
    code, message = _client_error(
        lambda: appconfig.get_environment(ApplicationId=app_id, EnvironmentId=env_id)
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == not_found, f"expected {not_found!r}, got {message!r}"

    # negative: deleting the already-deleted environment is rejected, effect stays absent
    code, message = _client_error(
        lambda: appconfig.delete_environment(ApplicationId=app_id, EnvironmentId=env_id)
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == not_found, f"expected {not_found!r}, got {message!r}"
    after2 = appconfig.list_environments(ApplicationId=app_id)["Items"]
    assert all(e["Id"] != env_id for e in after2), (
        f"expected {env_id} to stay absent after the rejected re-delete, got {after2!r}"
    )


def _client_error(fn):
    """Call fn(); return (code, message) of its botocore ClientError. An unexpected SUCCESS raises,
    because an emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
