"""concurrent-update-launch-configuration-template-disjoint-fields-merge."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-update-launch-configuration-template-disjoint-fields-merge"
GROUP = "launch-configuration-templates"
SERVICES = ["drs"]


@tags(
    "requires:drs-initialized",
    "axis:happy-path",
    "cap:c1",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """Two UpdateLaunchConfigurationTemplate calls on the same template, each naming a
    different field, both land: an update is a partial merge, never a full replace that
    drops a concurrent writer's field."""
    drs = ctx.client("drs")
    created = drs.create_launch_configuration_template(
        recoveryMode="FAST", launchDisposition="STOPPED"
    )
    template = created["launchConfigurationTemplate"]
    template_id = template["launchConfigurationTemplateID"]
    ctx.on_cleanup(
        lambda: drs.delete_launch_configuration_template(launchConfigurationTemplateID=template_id)
    )
    assert template["recoveryMode"] == "FAST", (
        f"initial recoveryMode was {template['recoveryMode']!r}"
    )
    assert template["launchDisposition"] == "STOPPED", (
        f"initial launchDisposition was {template['launchDisposition']!r}"
    )

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(
                drs.update_launch_configuration_template,
                launchConfigurationTemplateID=template_id,
                recoveryMode="OPTIMAL",
            ),
            pool.submit(
                drs.update_launch_configuration_template,
                launchConfigurationTemplateID=template_id,
                launchDisposition="STARTED",
            ),
        ]
        for f in futures:
            f.result()

    final = drs.describe_launch_configuration_templates(
        launchConfigurationTemplateIDs=[template_id]
    )["items"][0]
    assert final["recoveryMode"] == "OPTIMAL", (
        f"recoveryMode update was lost under concurrent writes: {final['recoveryMode']!r}"
    )
    assert final["launchDisposition"] == "STARTED", (
        f"launchDisposition update was lost under concurrent writes: {final['launchDisposition']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
