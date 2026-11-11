"""listjobs-maxresults-out-of-range-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "listjobs-maxresults-out-of-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["amplify"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListJobs rejects maxResults above the documented 0-50 bound but accepts the boundary value."""
    amplify = ctx.client("amplify")
    app_id = _create_app(ctx)

    branch_name = ctx.unique_name("branch-")
    amplify.create_branch(appId=app_id, branchName=branch_name)
    ctx.on_cleanup(lambda: _ignore(lambda: amplify.delete_branch(appId=app_id, branchName=branch_name)))

    err = _client_error(
        lambda: amplify.list_jobs(appId=app_id, branchName=branch_name, maxResults=51)
    )
    assert err == (
        "ValidationException",
        "1 validation error detected: Value '51' at 'maxResults' failed to satisfy constraint: "
        "Member must have value less than or equal to 50",
    ), err

    # Positive control: the documented upper bound itself is accepted.
    ok = amplify.list_jobs(appId=app_id, branchName=branch_name, maxResults=50)
    assert ok["jobSummaries"] == [], f"expected no jobs on a fresh branch, got {ok['jobSummaries']!r}"


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
    app = amplify.create_app(name=name)["app"]
    ctx.on_cleanup(lambda: _ignore(lambda: amplify.delete_app(appId=app["appId"])))
    return app["appId"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
