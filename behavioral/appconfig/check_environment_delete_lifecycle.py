"""environment-delete-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "environment-delete-lifecycle"
GROUP = 'environment'
SERVICES = ['appconfig']

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-environment-delete-lifecycle"}


def _client_error(fn):
    """Call fn(); return (code, message) of its botocore ClientError. An unexpected SUCCESS
    raises, because a target ACCEPTING a call real AWS refuses must not be reported as an
    error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A deleted environment, real before the delete, drops out of Get and List, and a later
    mutation against the same id fails with the same not-found code instead of being accepted.
    """
    ac = ctx.client("appconfig")
    app_id = ac.create_application(Name=ctx.unique_name("sim2real-behav-app-"), Tags=_TAGS)["Id"]
    ctx.on_cleanup(lambda: ac.delete_application(ApplicationId=app_id))
    env = ac.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-behav-env-"), Tags=_TAGS
    )
    env_id = env["Id"]

    # Positive control: the environment is real and visible before it is deleted, so the
    # not-found beats below prove a removal rather than a target that never created anything.
    got = ac.get_environment(ApplicationId=app_id, EnvironmentId=env_id)
    assert got["Id"] == env_id, f"expected freshly created environment {env_id!r}, got {got!r}"
    before = ac.list_environments(ApplicationId=app_id)["Items"]
    assert any(item["Id"] == env_id for item in before), (
        f"newly created environment {env_id!r} missing from list_environments before delete: "
        f"{before!r}"
    )

    ac.delete_environment(ApplicationId=app_id, EnvironmentId=env_id)

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    not_found = (
        f"Environment with Application Id {app_id} and Environment Id {env_id} "
        f"could not be found for account {account_id}."
    )
    code, message = _client_error(
        lambda: ac.get_environment(ApplicationId=app_id, EnvironmentId=env_id)
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    assert message == not_found, f"expected {not_found!r}, got {message!r}"
    after = ac.list_environments(ApplicationId=app_id)["Items"]
    assert all(item["Id"] != env_id for item in after), (
        f"deleted environment {env_id!r} still present in list_environments: {after!r}"
    )

    # Deletes prove unusable, not just gone: a second mutation against the dead id fails with
    # the same specific code rather than being silently accepted or misclassified.
    code, message = _client_error(
        lambda: ac.delete_environment(ApplicationId=app_id, EnvironmentId=env_id)
    )
    assert code == "ResourceNotFoundException", (
        f"delete of the already-deleted environment must fail with ResourceNotFoundException, "
        f"got {code!r}"
    )
    assert message == not_found, f"expected {not_found!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
