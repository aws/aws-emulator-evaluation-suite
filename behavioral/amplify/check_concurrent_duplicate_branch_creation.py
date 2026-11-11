"""concurrent-duplicate-branch-creation."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-duplicate-branch-creation"
GROUP = "concurrency"
SERVICES = ["amplify"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two concurrent CreateBranch calls for the same appId+branchName: exactly one wins."""
    amplify = ctx.client("amplify")
    app_id = _create_app(ctx)

    branch_name = ctx.unique_name("dup-branch-")
    ctx.on_cleanup(lambda: _ignore(lambda: amplify.delete_branch(appId=app_id, branchName=branch_name)))

    def _create():
        try:
            amplify.create_branch(appId=app_id, branchName=branch_name, tags={"sim2real": CHECK})
            return ("ok", None)
        except Exception as e:  # noqa: BLE001 - we classify below
            from botocore.exceptions import ClientError

            if isinstance(e, ClientError):
                err = e.response.get("Error", {})
                return ("error", (err.get("Code", ""), err.get("Message", "")))
            return ("error", ("unknown", str(e)))

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: _create(), range(2)))

    successes = [r for r in results if r[0] == "ok"]
    failures = [r for r in results if r[0] == "error"]
    assert len(successes) == 1, results
    assert len(failures) == 1, results
    assert failures[0][1] == (
        "BadRequestException",
        f"Failed to create branch. The branch {branch_name} already exists for the app {app_id}",
    ), failures

    branches = amplify.list_branches(appId=app_id)["branches"]
    matching = [b for b in branches if b["branchName"] == branch_name]
    assert len(matching) == 1, matching

    # The branch this check created is provably gone and unusable, and the
    # branchName is reusable once it is.
    amplify.delete_branch(appId=app_id, branchName=branch_name)
    gone = ("NotFoundException", f"Branch {branch_name} not found.")
    read_err = _client_error(lambda: amplify.get_branch(appId=app_id, branchName=branch_name))
    assert read_err == gone, f"expected {gone} reading deleted branch, got {read_err}"
    mutate_err = _client_error(lambda: amplify.update_branch(appId=app_id, branchName=branch_name))
    assert mutate_err == gone, f"expected {gone} mutating deleted branch, got {mutate_err}"
    branches_after_delete = amplify.list_branches(appId=app_id)["branches"]
    assert not any(b["branchName"] == branch_name for b in branches_after_delete), branches_after_delete

    recreated = amplify.create_branch(appId=app_id, branchName=branch_name, tags={"sim2real": CHECK})["branch"]
    assert recreated["branchName"] == branch_name, recreated


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


def _create_app(ctx) -> str:
    amplify = ctx.client("amplify")
    name = ctx.unique_name("sim2real-amplify-app-")
    app = amplify.create_app(name=name, tags={"sim2real": CHECK})["app"]
    ctx.on_cleanup(lambda: _ignore(lambda: amplify.delete_app(appId=app["appId"])))
    return app["appId"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
