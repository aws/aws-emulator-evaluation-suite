"""describe-configuration-options-catalog-constraints-typed."""
from __future__ import annotations


from behavioral_harness import tags

CHECK = "describe-configuration-options-catalog-constraints-typed"
GROUP = 'configuration-metadata'
SERVICES = ['elasticbeanstalk']

_STACK_CACHE = []

# The full set of ConfigurationOptionDescription.ValueType values Elastic Beanstalk publishes.
# If AWS publishes a value outside this set, the assertion below is what reports it.
_VALUE_TYPES = {"Scalar", "List", "Boolean", "CommaSeparatedList", "KeyValueList", "Json"}

# ChangeSeverity is the semantic an emulator flattens: it says what applying the option costs.
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


def _one(catalog, namespace, name):
    hits = [o for o in catalog if o.get("Namespace") == namespace and o.get("Name") == name]
    assert len(hits) == 1, (
        f"DescribeConfigurationOptions must describe exactly one ({namespace!r}, {name!r}), "
        f"got {hits!r}"
    )
    return hits[0]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The unfiltered DescribeConfigurationOptions catalog is typed reference data: every option has a
    ValueType and ChangeSeverity from the closed sets, enum/range/regex options publish their
    constraints, UserDefined is false throughout, and the stack name resolves to its PlatformArn.
    """
    eb = ctx.client("elasticbeanstalk")
    stack = _solution_stack(eb)
    resp = eb.describe_configuration_options(SolutionStackName=stack)

    assert resp["SolutionStackName"] == stack, (
        f"the response must echo the requested solution stack, got {resp.get('SolutionStackName')!r}"
    )
    # On real AWS: ConfigurationOptionsDescription carries
    # exactly SolutionStackName / PlatformArn / Options — there is NO Tier member in the response
    # (the Smithy output shape does not model one either), so the third field to pin is PlatformArn:
    # the option catalog resolves the requested stack NAME to the managed platform ARN that owns it.
    assert resp["PlatformArn"].startswith(f"arn:aws:elasticbeanstalk:{ctx.region}:"), (
        f"the catalog must resolve the requested stack to a platform ARN in the caller's region, "
        f"got {resp.get('PlatformArn')!r}"
    )
    assert ":platform/" in resp["PlatformArn"] and resp["PlatformArn"].rsplit("/", 1)[-1], (
        f"PlatformArn must name a versioned platform resource (.../platform/<name>/<version>), "
        f"got {resp.get('PlatformArn')!r}"
    )
    catalog = resp["Options"]
    assert len(catalog) > 50, (
        f"a solution stack publishes a large option grid; got only {len(catalog)} options"
    )

    # --- Every option is typed, and typed from the closed vocabularies. ---
    untyped = [
        (o.get("Namespace"), o.get("Name")) for o in catalog if o.get("ValueType") not in _VALUE_TYPES
    ]
    assert untyped == [], (
        f"every described option must carry a ValueType from {sorted(_VALUE_TYPES)}; "
        f"offenders: {untyped[:10]!r}"
    )
    unsevere = [
        (o.get("Namespace"), o.get("Name"))
        for o in catalog
        if o.get("ChangeSeverity") not in _CHANGE_SEVERITIES
    ]
    assert unsevere == [], (
        f"every described option must carry a ChangeSeverity from {sorted(_CHANGE_SEVERITIES)}; "
        f"offenders: {unsevere[:10]!r}"
    )
    assert all(isinstance(o.get("UserDefined"), bool) for o in catalog), (
        "every described option must carry a boolean UserDefined flag"
    )

    # --- ChangeSeverity discriminates: not every option is NoInterruption. ---
    severities = {o["ChangeSeverity"] for o in catalog}
    assert len(severities) >= 2, (
        f"ChangeSeverity must actually discriminate between options; the whole catalog reports "
        f"{severities!r} — an emulator that flattens it to one value has been caught"
    )

    # --- A constrained enum option publishes its ValueOptions. ---
    env_type = _one(catalog, "aws:elasticbeanstalk:environment", "EnvironmentType")
    assert set(env_type.get("ValueOptions") or []) == {"SingleInstance", "LoadBalanced"}, (
        f"aws:elasticbeanstalk:environment/EnvironmentType must publish exactly the two legal "
        f"values, got {env_type.get('ValueOptions')!r}"
    )
    # On real AWS: UserDefined does NOT mean "settable by the
    # customer" — every option in a solution-stack reference catalog reports
    # UserDefined=false, EnvironmentType included. The flag marks options the customer ADDED (e.g. a
    # key they invented in the free-form aws:elasticbeanstalk:application:environment namespace),
    # which by construction cannot appear in the platform's published catalog.
    assert env_type["UserDefined"] is False, (
        f"EnvironmentType is published by the platform, so the reference catalog reports "
        f"UserDefined=false, got {env_type['UserDefined']!r}"
    )
    assert [o for o in catalog if o["UserDefined"] is not False] == [], (
        f"no option in a solution-stack reference catalog is user-defined; offenders: "
        f"{[(o['Namespace'], o['Name']) for o in catalog if o['UserDefined'] is not False][:10]!r}"
    )

    # --- A ranged Scalar publishes its bounds and its default. ---
    min_size = _one(catalog, "aws:autoscaling:asg", "MinSize")
    assert min_size["ValueType"] == "Scalar", min_size
    assert int(min_size["MinValue"]) == 0, (
        f"aws:autoscaling:asg/MinSize publishes MinValue 0, got {min_size.get('MinValue')!r}"
    )
    assert int(min_size["MaxValue"]) == 10000, (
        f"aws:autoscaling:asg/MinSize publishes MaxValue 10000, got {min_size.get('MaxValue')!r}"
    )
    assert min_size["DefaultValue"] == "1", (
        f"aws:autoscaling:asg/MinSize publishes DefaultValue '1', got {min_size.get('DefaultValue')!r}"
    )
    assert min_size["ChangeSeverity"] == "NoInterruption", (
        f"changing MinSize does not interrupt the environment, got {min_size['ChangeSeverity']!r}"
    )
    assert min_size["UserDefined"] is False, (
        f"aws:autoscaling:asg/MinSize is a platform option, got UserDefined="
        f"{min_size['UserDefined']!r}"
    )

    # --- At least one option publishes a Regex constraint with both halves. ---
    regexed = [o for o in catalog if o.get("Regex")]
    assert regexed, (
        "the option catalog must publish at least one Regex-constrained option; an emulator that "
        "omits Regex entirely has dropped a whole class of published constraint"
    )
    for o in regexed:
        assert o["Regex"].get("Pattern"), (
            f"a Regex constraint must carry a Pattern, got {o['Regex']!r} on {o['Name']!r}"
        )
        assert o["Regex"].get("Label"), (
            f"a Regex constraint must carry a human-readable Label, got {o['Regex']!r} on "
            f"{o['Name']!r}"
        )

    # --- Requesting a subset returns only that subset, with the same constraint payload. ---
    subset = eb.describe_configuration_options(
        SolutionStackName=stack,
        Options=[{"Namespace": "aws:autoscaling:asg", "OptionName": "MinSize"}],
    )["Options"]
    assert len(subset) == 1, (
        f"an Options-filtered DescribeConfigurationOptions must return only the requested option, "
        f"got {[(o.get('Namespace'), o.get('Name')) for o in subset]!r}"
    )
    assert subset[0]["Namespace"] == "aws:autoscaling:asg" and subset[0]["Name"] == "MinSize", (
        f"an Options-filtered request for (aws:autoscaling:asg, MinSize) must return that option, "
        f"got ({subset[0].get('Namespace')!r}, {subset[0].get('Name')!r})"
    )
    assert subset[0]["MinValue"] == min_size["MinValue"], (
        "the filtered and unfiltered catalog must agree on the option's published bounds"
    )
    assert subset[0]["MaxValue"] == min_size["MaxValue"], (
        f"the filtered and unfiltered catalog must agree on MaxValue, got "
        f"{subset[0]['MaxValue']!r} vs {min_size['MaxValue']!r}"
    )
    assert subset[0]["DefaultValue"] == min_size["DefaultValue"], (
        f"the filtered and unfiltered catalog must agree on DefaultValue, got "
        f"{subset[0]['DefaultValue']!r} vs {min_size['DefaultValue']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
