"""create-get-delete-application."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-get-delete-application"
GROUP = 'lifecycle'
SERVICES = ['codedeploy']

def _create_application(ctx, compute_platform="Server"):
    cd = ctx.client("codedeploy")
    name = ctx.unique_name("sim2real-behav-app-")
    cd.create_application(
        applicationName=name,
        computePlatform=compute_platform,
        tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cd.delete_application(applicationName=name))
    return name


def _not_found(fn):
    """Call fn(); return its botocore error response; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateApplication -> GetApplication -> DeleteApplication; delete is terminal:
    an independent read of the dead id is rejected, and so is a mutation on it."""
    cd = ctx.client("codedeploy")
    name = _create_application(ctx)

    app = cd.get_application(applicationName=name)["application"]
    assert app["applicationName"] == name, app
    assert app["computePlatform"] == "Server", app
    assert app["linkedToGitHub"] is False, app
    assert "applicationId" in app and app["applicationId"], app

    cd.delete_application(applicationName=name)

    def _assert_not_found(fn, what):
        resp = _not_found(fn)
        err = resp["Error"]
        status = resp["ResponseMetadata"]["HTTPStatusCode"]
        assert err.get("Code") == "ApplicationDoesNotExistException", (
            f"{what}: expected ApplicationDoesNotExistException, got {err.get('Code')!r}"
        )
        assert status == 400, f"{what}: expected HTTP 400, got {status}"
        expected_message = f"No application found for name: {name}"
        assert err.get("Message") == expected_message, f'expected the message {expected_message!r}, got {err.get("Message")!r}'

    _assert_not_found(lambda: cd.get_application(applicationName=name), "GetApplication on the dead name")

    listed = []
    for page in cd.get_paginator("list_applications").paginate():
        listed.extend(page.get("applications", []))
    assert name not in listed, "ListApplications still holds the deleted application"

    _assert_not_found(
        lambda: cd.update_application(applicationName=name, newApplicationName=f"{name}-renamed"),
        "UpdateApplication on the dead name",
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
