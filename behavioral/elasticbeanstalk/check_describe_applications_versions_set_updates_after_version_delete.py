"""describe-applications-versions-set-updates-after-version-delete."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "describe-applications-versions-set-updates-after-version-delete"
GROUP = "application-versions"
SERVICES = ["elasticbeanstalk"]


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=5.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeApplications lists exactly the application's current version labels, and a
    DeleteApplicationVersion removes exactly the deleted label from that set and from
    DescribeApplicationVersions, leaving the other version untouched.
    """
    eb = ctx.client("elasticbeanstalk")
    app_name = ctx.unique_name("sim2real-behav-eb-app-")
    eb.create_application(ApplicationName=app_name, Tags=[{"Key": "sim2real", "Value": "true"}])
    ctx.on_cleanup(
        lambda _n=app_name: eb.delete_application(ApplicationName=_n, TerminateEnvByForce=True)
    )

    label_a = ctx.unique_name("sim2real-behav-v-a-")
    label_b = ctx.unique_name("sim2real-behav-v-b-")
    eb.create_application_version(ApplicationName=app_name, VersionLabel=label_a, Process=False)
    eb.create_application_version(ApplicationName=app_name, VersionLabel=label_b, Process=False)

    def versions():
        apps = eb.describe_applications(ApplicationNames=[app_name])["Applications"]
        return set(apps[0]["Versions"]) if apps else set()

    # Poll: DescribeApplications reflects new versions only after a delay.
    before = _poll_until(
        versions,
        lambda vs: vs == {label_a, label_b},
        description=f"DescribeApplications Versions set for {app_name} to contain both labels",
    )
    assert before == {label_a, label_b}, (
        f"DescribeApplications must list exactly both version labels before any delete, "
        f"expected {{{label_a!r}, {label_b!r}}}, got {before!r}"
    )

    eb.delete_application_version(
        ApplicationName=app_name, VersionLabel=label_a, DeleteSourceBundle=False
    )

    after = _poll_until(
        versions,
        lambda vs: vs == {label_b},
        description=(
            f"DescribeApplications Versions set for {app_name} to drop {label_a!r} and "
            f"retain only {label_b!r}"
        ),
    )
    assert after == {label_b}, (
        f"DescribeApplications must list exactly the remaining version label after the delete, "
        f"expected {{{label_b!r}}}, got {after!r}"
    )

    deleted = eb.describe_application_versions(
        ApplicationName=app_name, VersionLabels=[label_a]
    )["ApplicationVersions"]
    assert deleted == [], (
        f"DescribeApplicationVersions for the deleted label {label_a!r} must return an empty "
        f"list, got {deleted!r}"
    )

    remaining = eb.describe_application_versions(
        ApplicationName=app_name, VersionLabels=[label_b]
    )["ApplicationVersions"]
    assert [v["VersionLabel"] for v in remaining] == [label_b], (
        f"DescribeApplicationVersions for the surviving label {label_b!r} must still return it "
        f"intact, got {remaining!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
