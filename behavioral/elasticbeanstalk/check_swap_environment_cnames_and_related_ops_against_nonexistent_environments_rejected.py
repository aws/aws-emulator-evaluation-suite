"""swap-environment-cnames-and-related-ops-against-nonexistent-environments-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "swap-environment-cnames-and-related-ops-against-nonexistent-environments-rejected"
GROUP = "overly-permissive"
SERVICES = ["elasticbeanstalk"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SwapEnvironmentCNAMEs, ComposeEnvironments, RequestEnvironmentInfo and the managed-action
    operations reject environments and applications that were never created, with exact messages."""
    eb = ctx.client("elasticbeanstalk")
    fake_app = ctx.unique_name("sim2real-eb-app-ghost-")
    fake_env_a = ctx.unique_name("sim2real-eb-env-ghost-a-")
    fake_env_b = ctx.unique_name("sim2real-eb-env-ghost-b-")

    # SwapEnvironmentCNAMEs against two environments that were never created:
    # rejected, not a silent no-op.
    code, message = _error(
        lambda: eb.swap_environment_cnames(
            SourceEnvironmentName=fake_env_a, DestinationEnvironmentName=fake_env_b
        )
    )
    assert code == "InvalidParameterValue", f"swap_environment_cnames: {code}: {message}"
    expected = (
        f"source environment not found with Name: {fake_env_a} in account '{ctx.account}'"
    )
    assert message == expected, f"swap_environment_cnames: expected {expected!r}, got {message!r}"

    # ComposeEnvironments against an application that does not exist: rejected,
    # not treated as "zero environments to compose".
    code, message = _error(
        lambda: eb.compose_environments(
            ApplicationName=fake_app, VersionLabels=["nonexistent-version"]
        )
    )
    assert code == "MissingParameter", f"compose_environments: {code}: {message}"
    expected = "Application could not be found"
    assert message == expected, f"compose_environments: expected {expected!r}, got {message!r}"

    not_found = f"No Environment found for EnvironmentName = '{fake_env_a}'."

    # RequestEnvironmentInfo against a nonexistent environment: rejected, so no
    # collection pipeline is fabricated for an environment that never existed.
    code, message = _error(
        lambda: eb.request_environment_info(EnvironmentName=fake_env_a, InfoType="tail")
    )
    assert code == "InvalidParameterValue", f"request_environment_info: {code}: {message}"
    assert message == not_found, (
        f"request_environment_info: expected {not_found!r}, got {message!r}"
    )

    # ApplyEnvironmentManagedAction against a nonexistent environment and a
    # made-up ActionId: rejected, never "applied".
    code, message = _error(
        lambda: eb.apply_environment_managed_action(
            EnvironmentName=fake_env_a, ActionId="00000000-0000-0000-0000-000000000000"
        )
    )
    assert code == "InvalidParameterValue", f"apply_environment_managed_action: {code}: {message}"
    assert message == not_found, (
        f"apply_environment_managed_action: expected {not_found!r}, got {message!r}"
    )

    # DescribeEnvironmentManagedActions/History against a nonexistent
    # environment: rejected outright (not a silent "nothing to report" empty
    # list) - Elastic Beanstalk validates the environment reference before
    # answering either query.
    code, message = _error(
        lambda: eb.describe_environment_managed_actions(EnvironmentName=fake_env_a)
    )
    assert code == "InvalidParameterValue", f"describe_environment_managed_actions: {code}: {message}"
    assert message == not_found, (
        f"describe_environment_managed_actions: expected {not_found!r}, got {message!r}"
    )

    code, message = _error(
        lambda: eb.describe_environment_managed_action_history(EnvironmentName=fake_env_a)
    )
    assert code == "InvalidParameterValue", (
        f"describe_environment_managed_action_history: {code}: {message}"
    )
    assert message == not_found, (
        f"describe_environment_managed_action_history: expected {not_found!r}, got {message!r}"
    )


def _error(fn):
    """Return (Error.Code, Error.Message) of the ClientError fn() raises; a success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

