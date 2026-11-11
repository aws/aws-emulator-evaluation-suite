"""configuration-template-option-removal-falls-back-to-default."""
from __future__ import annotations


from behavioral_harness import tags

CHECK = "configuration-template-option-removal-falls-back-to-default"
GROUP = 'configuration-templates'
SERVICES = ['elasticbeanstalk']

_STACK_CACHE = []


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


def _value(settings, namespace, option_name):
    """The single resolved value for (namespace, option_name), or None when unresolved."""
    hits = [
        o
        for o in settings
        if o.get("Namespace") == namespace and o.get("OptionName") == option_name
    ]
    assert len(hits) <= 1, (
        f"({namespace!r}, {option_name!r}) must resolve to at most one setting, got {hits!r}"
    )
    return hits[0].get("Value") if hits else None


@tags("axis:happy-path", "cap:c1", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeConfigurationSettings returns the resolved option set including platform defaults,
    and OptionsToRemove makes an option fall back to its published DefaultValue, not vanish.

    Reference: https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/command-options.html
    """
    eb = ctx.client("elasticbeanstalk")
    tag = [{"Key": "sim2real", "Value": "eb-option-removal-fallback"}]
    app_name = ctx.unique_name("sim2real-behav-eb-app-")
    eb.create_application(ApplicationName=app_name, Tags=tag)
    ctx.on_cleanup(
        lambda _n=app_name: eb.delete_application(ApplicationName=_n, TerminateEnvByForce=True)
    )

    ns = "aws:autoscaling:asg"
    stack = _solution_stack(eb)

    # The published default is the value the option MUST fall back to.
    described = [
        o
        for o in eb.describe_configuration_options(SolutionStackName=stack)["Options"]
        if o.get("Namespace") == ns and o.get("Name") == "MinSize"
    ]
    assert len(described) == 1, f"{ns}/MinSize must be described exactly once, got {described!r}"
    default_value = described[0]["DefaultValue"]
    assert default_value, f"{ns}/MinSize must publish a DefaultValue, got {described[0]!r}"

    override = str(int(default_value) + 2)
    template_name = ctx.unique_name("sim2real-behav-eb-tmpl-")
    eb.create_configuration_template(
        ApplicationName=app_name,
        TemplateName=template_name,
        SolutionStackName=stack,
        OptionSettings=[{"Namespace": ns, "OptionName": "MinSize", "Value": override}],
        Tags=tag,
    )
    ctx.on_cleanup(
        lambda _a=app_name, _t=template_name: eb.delete_configuration_template(
            ApplicationName=_a, TemplateName=_t
        )
    )

    record = eb.describe_configuration_settings(
        ApplicationName=app_name, TemplateName=template_name
    )["ConfigurationSettings"][0]
    assert record["TemplateName"] == template_name, record
    assert record["ApplicationName"] == app_name, record
    assert record["SolutionStackName"] == stack, record
    assert record["DeploymentStatus"] == "deployed", (
        f"a saved configuration template reports DeploymentStatus 'deployed', got "
        f"{record.get('DeploymentStatus')!r}"
    )
    assert record.get("DateCreated") is not None, record
    assert record.get("DateUpdated") is not None, record
    assert "EnvironmentName" not in record, (
        f"a template-scoped configuration record must not carry an EnvironmentName, got {record!r}"
    )

    resolved = record["OptionSettings"]

    # The resolved set is a strict superset of what was written.
    assert _value(resolved, ns, "MinSize") == override, (
        f"the explicit override must win, got {_value(resolved, ns, 'MinSize')!r}"
    )
    assert len(resolved) > 1, (
        f"DescribeConfigurationSettings must return the RESOLVED set (platform defaults plus the "
        f"one override), not just the written option; got {len(resolved)} settings: {resolved!r}"
    )
    inherited_max = _value(resolved, ns, "MaxSize")
    assert inherited_max is not None, (
        f"{ns}/MaxSize was never written by this check and must still resolve from the platform "
        f"default; the resolved set contains only "
        f"{sorted({(o.get('Namespace'), o.get('OptionName')) for o in resolved})!r}"
    )
    max_default = [
        o
        for o in eb.describe_configuration_options(SolutionStackName=stack)["Options"]
        if o.get("Namespace") == ns and o.get("Name") == "MaxSize"
    ][0]["DefaultValue"]
    assert inherited_max == max_default, (
        f"the inherited {ns}/MaxSize must equal the DefaultValue the catalog publishes "
        f"({max_default!r}), got {inherited_max!r}"
    )

    eb.update_configuration_template(
        ApplicationName=app_name,
        TemplateName=template_name,
        OptionsToRemove=[{"Namespace": ns, "OptionName": "MinSize"}],
    )
    after = eb.describe_configuration_settings(
        ApplicationName=app_name, TemplateName=template_name
    )["ConfigurationSettings"][0]["OptionSettings"]
    fallen_back = _value(after, ns, "MinSize")
    assert fallen_back is not None, (
        f"after OptionsToRemove, {ns}/MinSize must resolve to the inherited platform default, not "
        f"disappear from the resolved set"
    )
    assert fallen_back == default_value, (
        f"after OptionsToRemove, {ns}/MinSize must resolve to the published DefaultValue "
        f"{default_value!r}, got {fallen_back!r}"
    )
    assert _value(after, ns, "MaxSize") == max_default, (
        "removing MinSize must not disturb the sibling MaxSize resolution"
    )

    # The fallback is not sticky: re-applying the override restores it.
    eb.update_configuration_template(
        ApplicationName=app_name,
        TemplateName=template_name,
        OptionSettings=[{"Namespace": ns, "OptionName": "MinSize", "Value": override}],
    )
    restored = eb.describe_configuration_settings(
        ApplicationName=app_name, TemplateName=template_name
    )["ConfigurationSettings"][0]["OptionSettings"]
    assert _value(restored, ns, "MinSize") == override, (
        f"an override re-applied after removal must take effect again, got "
        f"{_value(restored, ns, 'MinSize')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
