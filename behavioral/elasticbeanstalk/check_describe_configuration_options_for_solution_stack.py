"""describe-configuration-options-for-solution-stack."""
from __future__ import annotations


from behavioral_harness import tags

CHECK = "describe-configuration-options-for-solution-stack"
GROUP = 'configuration-metadata'
SERVICES = ['elasticbeanstalk']

_STACK_CACHE = []

# The full set of ConfigurationOptionDescription.ValueType values Elastic Beanstalk publishes, and
# the closed set of ChangeSeverity values (what applying the option costs).
_VALUE_TYPES = {"Scalar", "List", "Boolean", "CommaSeparatedList", "KeyValueList", "Json"}
_CHANGE_SEVERITIES = {"NoInterruption", "RestartApplicationServer", "RestartEnvironment", "Unknown"}


def _solution_stack(eb):
    """A usable SolutionStackName, preferring a current AL2023 Docker/Python stack."""
    if not _STACK_CACHE:
        _STACK_CACHE.extend(eb.list_available_solution_stacks().get("SolutionStacks") or [])
    stacks = list(_STACK_CACHE)
    if not stacks:
        raise AssertionError("No solution stacks available from ListAvailableSolutionStacks")
    preferred = (
        [s for s in stacks if "Amazon Linux 2023" in s and "running Docker" in s]
        or [s for s in stacks if "Amazon Linux 2023" in s and "running Python" in s]
        or [s for s in stacks if "Amazon Linux 2023" in s]
        or [s for s in stacks if "running Docker" in s]
    )
    return (preferred or stacks)[0]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeConfigurationOptions returns option definitions with value constraints."""
    eb = ctx.client("elasticbeanstalk")
    stack = _solution_stack(eb)
    resp = eb.describe_configuration_options(SolutionStackName=stack)
    assert resp["SolutionStackName"] == stack, (
        f"the response must echo the requested solution stack, got {resp.get('SolutionStackName')!r}"
    )
    options = resp["Options"]
    assert len(options) > 10, "a solution stack must expose many configuration options"

    instance_type = [
        o
        for o in options
        if o["Namespace"] == "aws:autoscaling:launchconfiguration"
        and o["Name"] == "InstanceType"
    ]
    assert len(instance_type) == 1, "InstanceType option must be described for the stack"
    value_type = instance_type[0].get("ValueType")
    change_severity = instance_type[0].get("ChangeSeverity")
    assert value_type in _VALUE_TYPES, (
        f"InstanceType's ValueType must be one of {sorted(_VALUE_TYPES)}, got {value_type!r} "
        "(an emulator that stamps an arbitrary placeholder is caught here)"
    )
    assert change_severity in _CHANGE_SEVERITIES, (
        f"InstanceType's ChangeSeverity must be one of {sorted(_CHANGE_SEVERITIES)}, got "
        f"{change_severity!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
