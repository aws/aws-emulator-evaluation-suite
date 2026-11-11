"""get-application-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-application-not-found"
GROUP = 'error-semantics'
SERVICES = ['codedeploy']

def _error(fn):
    """Call fn(); return (code, message) of its botocore error. An unexpected SUCCESS raises,
    because a target accepting a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetApplication on an unknown name -> ApplicationDoesNotExistException."""
    cd = ctx.client("codedeploy")
    # A region that has never held an application answers with an account-level message
    # instead of the per-name one, so the check creates its own application first: that
    # pins the per-name form and doubles as the positive control.
    real_app = ctx.unique_name("sim2real-behav-" + "real-app-")
    cd.create_application(applicationName=real_app, computePlatform="Server")
    ctx.on_cleanup(lambda: cd.delete_application(applicationName=real_app))
    got = cd.get_application(applicationName=real_app)["application"]
    assert got["applicationName"] == real_app, got

    ghost = ctx.unique_name("sim2real-behav-" + "ghost-app-")
    code, message = _error(lambda: cd.get_application(applicationName=ghost))
    assert code == "ApplicationDoesNotExistException", code
    assert message == f"No application found for name: {ghost}", message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
