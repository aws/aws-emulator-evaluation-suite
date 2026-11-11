"""create-application-version-unknown-application-must-fail."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-application-version-unknown-application-must-fail"
GROUP = 'overly-permissive'
SERVICES = ['elasticbeanstalk']

def _err(fn):
    """Call fn(); return the botocore (Code, Message) if a ClientError is raised. An unexpected
    SUCCESS raises, because an emulator accepting input real AWS refuses is the strongest signal
    available."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(
        f"CreateApplicationVersion against an unknown application should fail, but it "
        f"SUCCEEDED and returned {result!r}"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateApplicationVersion without AutoCreateApplication must not invent the application."""
    eb = ctx.client("elasticbeanstalk")

    real_app = ctx.unique_name("sim2real-behav-eb-app-real-")
    eb.create_application(ApplicationName=real_app, Tags=[{"Key": "sim2real", "Value": "true"}])
    ctx.on_cleanup(
        lambda _n=real_app: eb.delete_application(ApplicationName=_n, TerminateEnvByForce=True)
    )
    control_label = ctx.unique_name("sim2real-behav-v-control-")
    eb.create_application_version(
        ApplicationName=real_app, VersionLabel=control_label, AutoCreateApplication=False
    )
    control_listed = eb.describe_application_versions(
        ApplicationName=real_app, VersionLabels=[control_label]
    )["ApplicationVersions"]
    assert len(control_listed) == 1, (
        f"positive control: CreateApplicationVersion against a real application with "
        f"AutoCreateApplication=False must succeed and be visible, got {control_listed!r}"
    )

    app_name = ctx.unique_name("sim2real-behav-eb-app-absent-")
    label = ctx.unique_name("sim2real-behav-v-")

    code, message = _err(
        lambda: eb.create_application_version(
            ApplicationName=app_name, VersionLabel=label, AutoCreateApplication=False
        )
    )
    assert code == "InvalidParameterValue", (
        f"CreateApplicationVersion against an unknown application must fail with "
        f"InvalidParameterValue, got {code!r}"
    )
    expected = f"No Application named '{app_name}' found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    listed = eb.describe_applications(ApplicationNames=[app_name])["Applications"]
    assert listed == [], "a rejected version creation must not auto-create the application"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
