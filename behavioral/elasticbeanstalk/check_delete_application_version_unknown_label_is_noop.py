"""delete-application-version-unknown-label-is-noop."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "delete-application-version-unknown-label-is-noop"
GROUP = 'application-versions'
SERVICES = ['elasticbeanstalk']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteApplicationVersion for a label that never existed is a silent no-op on real EB."""
    eb = ctx.client("elasticbeanstalk")
    app_name = ctx.unique_name("sim2real-behav-eb-app-")
    eb.create_application(ApplicationName=app_name)
    ctx.on_cleanup(lambda _n=app_name: eb.delete_application(ApplicationName=_n, TerminateEnvByForce=True))

    label = ctx.unique_name("sim2real-behav-v-")
    eb.create_application_version(ApplicationName=app_name, VersionLabel=label)

    # Deleting a label that was never created must not raise ...
    eb.delete_application_version(
        ApplicationName=app_name, VersionLabel=ctx.unique_name("sim2real-behav-v-absent-")
    )
    # ... and must not disturb the version that does exist.
    versions = eb.describe_application_versions(ApplicationName=app_name)[
        "ApplicationVersions"
    ]
    assert [v["VersionLabel"] for v in versions] == [label], (
        "a no-op version delete must leave existing versions untouched"
    )

    # Deleting the same real version twice is likewise tolerated.
    eb.delete_application_version(ApplicationName=app_name, VersionLabel=label)
    eb.delete_application_version(ApplicationName=app_name, VersionLabel=label)
    after = eb.describe_application_versions(ApplicationName=app_name)[
        "ApplicationVersions"
    ]
    assert after == [], "the deleted version must be gone after repeated deletes"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
