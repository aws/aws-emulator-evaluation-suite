"""delete-application-version-unknown-application-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-application-version-unknown-application-rejected"
GROUP = "application-versions"
SERVICES = ["elasticbeanstalk"]


def _err(fn):
    """Call fn(); return the botocore (Code, Message) of the ClientError it raises. A call that
    succeeds raises instead."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(
        f"DeleteApplicationVersion against an unknown application should fail, but it "
        f"SUCCEEDED and returned {result!r}"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteApplicationVersion naming an application that does not exist is refused and leaves
    the real version, under the real application, untouched.
    """
    eb = ctx.client("elasticbeanstalk")
    app_name = ctx.unique_name("sim2real-behav-eb-app-")
    eb.create_application(ApplicationName=app_name, Tags=[{"Key": "sim2real", "Value": "true"}])
    ctx.on_cleanup(
        lambda _n=app_name: eb.delete_application(ApplicationName=_n, TerminateEnvByForce=True)
    )

    label = ctx.unique_name("sim2real-behav-v-")
    eb.create_application_version(ApplicationName=app_name, VersionLabel=label, Process=False)

    bogus_app = ctx.unique_name("sim2real-behav-eb-app-missing-")
    code, message = _err(
        lambda: eb.delete_application_version(
            ApplicationName=bogus_app, VersionLabel=label, DeleteSourceBundle=False
        )
    )
    assert code == "InvalidParameterValue", (
        f"DeleteApplicationVersion against an unknown application must fail with "
        f"InvalidParameterValue, got {code!r}"
    )
    expected = f"No Application named '{bogus_app}' found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    untouched = eb.describe_application_versions(
        ApplicationName=app_name, VersionLabels=[label]
    )["ApplicationVersions"]
    assert [v["VersionLabel"] for v in untouched] == [label], (
        f"the refused delete must not disturb the real version {label!r} under the real "
        f"application {app_name!r}, got {untouched!r}"
    )

    # Positive control: the same operation, naming the correct application, succeeds.
    eb.delete_application_version(
        ApplicationName=app_name, VersionLabel=label, DeleteSourceBundle=False
    )
    gone = eb.describe_application_versions(
        ApplicationName=app_name, VersionLabels=[label]
    )["ApplicationVersions"]
    assert gone == [], (
        f"positive control: DeleteApplicationVersion against the real application must "
        f"actually delete the version, got {gone!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
