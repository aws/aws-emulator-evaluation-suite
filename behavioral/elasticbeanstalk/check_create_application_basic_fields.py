"""create-application-basic-fields."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "create-application-basic-fields"
GROUP = 'applications'
SERVICES = ['elasticbeanstalk']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateApplication returns the application with the requested name/description populated."""
    eb = ctx.client("elasticbeanstalk")
    name = ctx.unique_name("sim2real-behav-eb-app-")
    resp = eb.create_application(
        ApplicationName=name,
        Description="fidelity test app",
        Tags=[{"Key": "sim2real", "Value": "create-application-basic-fields"}],
    )
    ctx.on_cleanup(lambda _n=name: eb.delete_application(ApplicationName=_n, TerminateEnvByForce=True))
    app = resp["Application"]
    assert app["ApplicationName"] == name, f"expected ApplicationName {name!r}, got {app.get('ApplicationName')!r}"
    assert app["Description"] == "fidelity test app", (
        f"expected Description 'fidelity test app', got {app.get('Description')!r}"
    )
    assert "ApplicationArn" in app, f"expected ApplicationArn in create response, got keys {list(app.keys())}"

    described = eb.describe_applications(ApplicationNames=[name])
    apps = described["Applications"]
    assert len(apps) == 1, f"expected exactly 1 application named {name!r}, got {len(apps)}"
    assert apps[0]["ApplicationName"] == name, (
        f"expected DescribeApplications ApplicationName {name!r}, got {apps[0].get('ApplicationName')!r}"
    )
    assert apps[0]["Description"] == "fidelity test app", (
        f"expected DescribeApplications Description 'fidelity test app', got {apps[0].get('Description')!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
