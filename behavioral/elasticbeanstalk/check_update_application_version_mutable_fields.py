"""update-application-version-mutable-fields."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "update-application-version-mutable-fields"
GROUP = 'application-versions'
SERVICES = ['elasticbeanstalk']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateApplicationVersion changes Description but leaves identity fields untouched."""
    eb = ctx.client("elasticbeanstalk")
    app_name = ctx.unique_name("sim2real-behav-eb-app-")
    eb.create_application(ApplicationName=app_name, Tags=[{"Key": "sim2real", "Value": "true"}])
    ctx.on_cleanup(lambda _n=app_name: eb.delete_application(ApplicationName=_n, TerminateEnvByForce=True))

    version_label = ctx.unique_name("sim2real-behav-v-")
    created = eb.create_application_version(
        ApplicationName=app_name,
        VersionLabel=version_label,
        Description="before",
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )["ApplicationVersion"]

    mutate_resp = eb.update_application_version(
        ApplicationName=app_name, VersionLabel=version_label, Description="after"
    )["ApplicationVersion"]
    assert mutate_resp["Description"] == "after", (
        f"UpdateApplicationVersion's own response did not echo the new Description: {mutate_resp!r}"
    )

    described = eb.describe_application_versions(
        ApplicationName=app_name, VersionLabels=[version_label]
    )["ApplicationVersions"]
    assert len(described) == 1, f"expected exactly one version at the destination, got {described!r}"
    av = described[0]
    assert av["Description"] == "after", (
        f"independent DescribeApplicationVersions read expected Description='after', got {av['Description']!r}"
    )
    assert av["ApplicationName"] == app_name, (
        f"identity field ApplicationName drifted: expected {app_name!r}, got {av['ApplicationName']!r}"
    )
    assert av["VersionLabel"] == version_label, (
        f"identity field VersionLabel drifted: expected {version_label!r}, got {av['VersionLabel']!r}"
    )
    assert av["DateCreated"] == created["DateCreated"], (
        f"immutable DateCreated changed on update: expected {created['DateCreated']!r}, got {av['DateCreated']!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
