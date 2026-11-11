"""branch-initial-job-state."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "branch-initial-job-state"
GROUP = "state"
SERVICES = ["amplify"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A freshly created branch has no active job and zero job history, and an independent
    ListJobs at the destination confirms the job history is actually empty, not just reported
    as such by the branch record."""
    amplify = ctx.client("amplify")
    app_id = _create_app(ctx)

    branch_name = ctx.unique_name("branch-")
    branch = amplify.create_branch(
        appId=app_id,
        branchName=branch_name,
        tags={"sim2real:managed": "true", "sim2real:check": CHECK},
    )["branch"]
    ctx.on_cleanup(lambda: _ignore(lambda: amplify.delete_branch(appId=app_id, branchName=branch_name)))

    assert branch.get("activeJobId", "") == "", (
        f"expected no activeJobId on CreateBranch response, got {branch.get('activeJobId')!r}"
    )
    assert branch["totalNumberOfJobs"] == "0", (
        f"expected totalNumberOfJobs '0' on CreateBranch response, got {branch['totalNumberOfJobs']!r}"
    )

    # Terminal assertions are on an independent GetBranch read, not the CreateBranch response.
    fetched = amplify.get_branch(appId=app_id, branchName=branch_name)["branch"]
    assert fetched.get("activeJobId", "") == "", (
        f"expected no activeJobId on GetBranch, got {fetched.get('activeJobId')!r}"
    )
    assert fetched["totalNumberOfJobs"] == "0", (
        f"expected totalNumberOfJobs '0' on GetBranch, got {fetched['totalNumberOfJobs']!r}"
    )

    # Independent side-channel: confirm the job history is actually empty via ListJobs, rather than
    # trusting the branch record's own self-reported totalNumberOfJobs field.
    jobs = amplify.list_jobs(appId=app_id, branchName=branch_name)["jobSummaries"]
    assert jobs == [], f"expected zero job history via ListJobs, got {len(jobs)} job(s): {jobs!r}"


def _ignore(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _create_app(ctx) -> str:
    amplify = ctx.client("amplify")
    name = ctx.unique_name("sim2real-amplify-app-")
    app = amplify.create_app(name=name, tags={"sim2real:managed": "true", "sim2real:check": CHECK})["app"]
    ctx.on_cleanup(lambda: _ignore(lambda: amplify.delete_app(appId=app["appId"])))
    return app["appId"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
