"""describe-environments-unknown-name-returns-empty."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "describe-environments-unknown-name-returns-empty"
GROUP = 'environment-lifecycle'
SERVICES = ['elasticbeanstalk']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeEnvironments for an unknown environment name returns an empty list, not an
    error — proven against a target that also has a real, live environment on hand, so a
    stub that answers empty for every name cannot pass this by construction."""
    eb = ctx.client("elasticbeanstalk")
    app_name = ctx.unique_name("sim2real-eb-app-")
    env_name = ctx.unique_name("sim2real-eb-env-")
    eb.create_application(ApplicationName=app_name, Tags=[{"Key": "sim2real", "Value": "true"}])
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=True))

    stack = _pick_solution_stack(eb)
    eb.create_environment(
        ApplicationName=app_name,
        EnvironmentName=env_name,
        SolutionStackName=stack,
        OptionSettings=[
            {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "InstanceType", "Value": "t3.micro"},
            {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType", "Value": "SingleInstance"},
        ],
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: eb.terminate_environment(EnvironmentName=env_name))

    # Positive control: the real, live environment is visible by name.
    live = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=True)["Environments"]
    assert live and live[0]["EnvironmentName"] == env_name, (
        f"DescribeEnvironments must return the live environment by name, got {live!r}"
    )

    # Negative: a name that was never created returns an empty list, not an error.
    absent = eb.describe_environments(
        EnvironmentNames=[ctx.unique_name("sim2real-eb-absent-")], IncludeDeleted=True
    )["Environments"]
    assert absent == [], (
        f"DescribeEnvironments must return an empty list for unknown names, got {absent!r}"
    )


def _pick_solution_stack(eb) -> str:
    stacks = eb.list_available_solution_stacks()["SolutionStacks"]
    for s in stacks:
        if "Amazon Linux" in s and "running" in s and "Docker" not in s:
            return s
    return stacks[0]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
