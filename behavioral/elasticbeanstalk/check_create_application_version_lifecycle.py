"""create-application-version-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "create-application-version-lifecycle"
GROUP = 'application-versions'
SERVICES = ['elasticbeanstalk']

# The harness's per-check budget: the post-delete convergence wait ends only where the runner
# would stop the check anyway, so it is not an assertion on elapsed time.
_SUITE_BUDGET_S = 3600


def _assert_invalid_parameter(fn, what, expected_message):
    """fn() must fail with InvalidParameterValue / an HTTP 4xx and the exact message; a success raises.

    The API reference documents InvalidParameterValue for an unknown application or version label."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        status = exc.response["ResponseMetadata"]["HTTPStatusCode"]
    else:
        raise AssertionError(f"{what}: expected InvalidParameterValue, the call SUCCEEDED: {result!r}")
    assert err.get("Code") == "InvalidParameterValue", (
        f"{what}: expected InvalidParameterValue, got {err.get('Code')!r}"
    )
    assert isinstance(status, int) and 400 <= status < 500, f"{what}: expected HTTP 4xx, got {status}"
    assert err.get("Message") == expected_message, f'expected the message {expected_message!r}, got {err.get("Message")!r}'


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateApplicationVersion -> DescribeApplicationVersions -> DeleteApplicationVersion round-trips."""
    eb = ctx.client("elasticbeanstalk")
    app_name = ctx.unique_name("sim2real-behav-eb-app-")
    eb.create_application(ApplicationName=app_name)
    # the body deletes the application; the teardown removes it only if the body stopped earlier
    ctx.on_cleanup(
        lambda _n=app_name: eb.describe_applications(ApplicationNames=[_n])["Applications"]
        and eb.delete_application(ApplicationName=_n, TerminateEnvByForce=True)
    )

    version_label = ctx.unique_name("sim2real-behav-v-")
    resp = eb.create_application_version(
        ApplicationName=app_name, VersionLabel=version_label, Description="v1"
    )
    av = resp["ApplicationVersion"]
    assert av["ApplicationName"] == app_name, (
        f"CreateApplicationVersion must echo the ApplicationName, expected {app_name!r} got {av.get('ApplicationName')!r}"
    )
    assert av["VersionLabel"] == version_label, (
        f"CreateApplicationVersion must echo the VersionLabel, expected {version_label!r} got {av.get('VersionLabel')!r}"
    )

    described = eb.describe_application_versions(
        ApplicationName=app_name, VersionLabels=[version_label]
    )
    assert len(described["ApplicationVersions"]) == 1, (
        f"expected exactly 1 application version for {version_label!r}, got {len(described['ApplicationVersions'])}"
    )
    assert described["ApplicationVersions"][0]["VersionLabel"] == version_label, (
        f"DescribeApplicationVersions must round-trip VersionLabel, expected {version_label!r} got {described['ApplicationVersions'][0].get('VersionLabel')!r}"
    )

    eb.delete_application_version(
        ApplicationName=app_name, VersionLabel=version_label
    )
    # beat 1: Elastic Beanstalk's read-by-id answers an empty list for a removed version
    described_after = eb.describe_application_versions(
        ApplicationName=app_name, VersionLabels=[version_label]
    )
    assert described_after["ApplicationVersions"] == [], (
        f"DescribeApplicationVersions by label must be empty after the delete, got "
        f"{[v.get('VersionLabel') for v in described_after['ApplicationVersions']]!r}"
    )
    # beat 2: the application's version listing no longer holds it
    labels = [
        v["VersionLabel"]
        for page in eb.get_paginator("describe_application_versions").paginate(ApplicationName=app_name)
        for v in page["ApplicationVersions"]
    ]
    assert version_label not in labels, "DescribeApplicationVersions(ApplicationName) still holds the deleted version"
    # beat 3: a mutation on the dead label is refused
    _assert_invalid_parameter(
        lambda: eb.update_application_version(
            ApplicationName=app_name, VersionLabel=version_label, Description="post-delete"
        ),
        "UpdateApplicationVersion on the deleted version",
        expected_message=f"Application version with label '{version_label}' not found in application '{app_name}'",
    )

    eb.delete_application(ApplicationName=app_name)
    # DeleteApplication converges: the read by name is polled to empty, bounded by the budget.
    deadline = time.monotonic() + _SUITE_BUDGET_S
    while True:
        gone = eb.describe_applications(ApplicationNames=[app_name])["Applications"]
        if gone == [] or time.monotonic() >= deadline:
            break
        time.sleep(2)
    assert gone == [], (
        f"DescribeApplications by name must be empty after the delete, got "
        f"{[a.get('ApplicationName') for a in gone]!r}"
    )
    names = [a["ApplicationName"] for a in eb.describe_applications()["Applications"]]
    assert app_name not in names, "DescribeApplications still holds the deleted application"
    _assert_invalid_parameter(
        lambda: eb.update_application(ApplicationName=app_name, Description="post-delete"),
        "UpdateApplication on the deleted application",
        expected_message=f"No Application named '{app_name}' found.",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
