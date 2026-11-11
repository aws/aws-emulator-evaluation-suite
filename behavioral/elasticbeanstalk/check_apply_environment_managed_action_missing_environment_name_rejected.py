"""apply-environment-managed-action-missing-environment-name-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "apply-environment-managed-action-missing-environment-name-rejected"
GROUP = "overly-permissive"
SERVICES = ["elasticbeanstalk"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ApplyEnvironmentManagedAction with only a bogus ActionId fails with MissingParameter, and with a
    never-created EnvironmentName with InvalidParameterValue naming it, each with its exact message, and no
    environment of that name exists."""
    eb = ctx.client("elasticbeanstalk")

    bogus_action_id = ctx.unique_name("sim2real-eb-bogus-action-")
    code, message = _error_code(lambda: eb.apply_environment_managed_action(ActionId=bogus_action_id))
    assert code == "MissingParameter", (
        f"expected MissingParameter when ActionId is given without EnvironmentName/EnvironmentId, got {code}"
    )
    expected = "You must specify either EnvironmentName or EnvironmentId."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    bogus_env_name = ctx.unique_name("sim2real-eb-ghost-")
    code_with_env, message_with_env = _error_code(
        lambda: eb.apply_environment_managed_action(ActionId=bogus_action_id, EnvironmentName=bogus_env_name)
    )
    assert code_with_env == "InvalidParameterValue", (
        f"expected InvalidParameterValue for a nonexistent EnvironmentName, got {code_with_env}"
    )
    expected_with_env = f"No Environment found for EnvironmentName = '{bogus_env_name}'."
    assert message_with_env == expected_with_env, (
        f"expected message {expected_with_env!r}, got {message_with_env!r}"
    )

    # The bogus environment name must never correspond to a real environment record.
    ghost = eb.describe_environments(EnvironmentNames=[bogus_env_name], IncludeDeleted=False)["Environments"]
    assert ghost == [], f"unexpected environment materialized for a bogus name: {ghost}"


def _error_code(fn):
    """Call fn(); return its botocore (Code, Message). An unexpected success raises, so an
    emulator accepting a call real AWS refuses is not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        error = err.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
