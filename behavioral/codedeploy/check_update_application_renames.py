"""update-application-renames."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-application-renames"
GROUP = 'lifecycle'
SERVICES = ['codedeploy']

def _create_application(ctx, compute_platform="Server"):
    cd = ctx.client("codedeploy")
    name = ctx.unique_name("sim2real-behav-app-")
    cd.create_application(
        applicationName=name,
        computePlatform=compute_platform,
        tags=[{"Key": "sim2real:managed", "Value": "true"},
              {"Key": "sim2real", "Value": CHECK}],
    )
    return name


def _client_error(fn):
    """Call fn(); return its botocore error as (code, message). An unexpected SUCCESS raises,
    because an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateApplication renames in place: the new name resolves, the old does not."""
    cd = ctx.client("codedeploy")
    name = _create_application(ctx)
    new_name = ctx.unique_name("sim2real-behav-" + "app-renamed-")

    # A single live_name holder — the application is renamed in place, so exactly
    # one delete must fire, against whichever name is current at cleanup time.
    live_name = {"name": name}
    ctx.on_cleanup(lambda: cd.delete_application(applicationName=live_name["name"]))

    cd.update_application(applicationName=name, newApplicationName=new_name)
    live_name["name"] = new_name

    app = cd.get_application(applicationName=new_name)["application"]
    assert app["applicationName"] == new_name, app

    error = _client_error(lambda: cd.get_application(applicationName=name))
    assert error == (
        "ApplicationDoesNotExistException",
        f"No application found for name: {name}",
    ), error


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
