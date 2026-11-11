"""delete-app-cascades-to-branches."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-app-cascades-to-branches"
GROUP = "lifecycle"
SERVICES = ["amplify"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Deleting an app removes it and cascades so its branches are no longer reachable."""
    amplify = ctx.client("amplify")
    name = ctx.unique_name("sim2real-amplify-app-")
    app = amplify.create_app(name=name, tags={"sim2real": "true"})["app"]
    app_id = app["appId"]
    ctx.on_cleanup(lambda: _ignore(lambda: amplify.delete_app(appId=app_id)))

    branch_name = ctx.unique_name("branch-")
    amplify.create_branch(appId=app_id, branchName=branch_name, tags={"sim2real": "true"})
    ctx.on_cleanup(lambda: _ignore(lambda: amplify.delete_branch(appId=app_id, branchName=branch_name)))

    amplify.delete_app(appId=app_id)

    app_gone = ("NotFoundException", f"App {app_id} not found.")
    err_app = _client_error(lambda: amplify.get_app(appId=app_id))
    assert err_app == app_gone, err_app

    err_branch = _client_error(lambda: amplify.get_branch(appId=app_id, branchName=branch_name))
    assert err_branch == app_gone, err_branch

    # The app id is genuinely dead, not merely unreadable: a mutation against it
    # (creating a new branch under the deleted app) must also fail.
    other_branch_name = ctx.unique_name("branch-")
    remutate_err = _client_error(
        lambda: amplify.create_branch(appId=app_id, branchName=other_branch_name)
    )
    assert remutate_err == app_gone, remutate_err


def _ignore(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _client_error(fn) -> tuple[str, str]:
    """Call fn() and return its (code, message); an unexpected success raises, so an emulator
    accepting a call real AWS refuses never reads as a mere code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(f"expected a ClientError, call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
