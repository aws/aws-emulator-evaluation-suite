"""list-branches-pagination."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-branches-pagination"
GROUP = "state"
SERVICES = ["amplify"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListBranches paginates with maxResults/nextToken and returns every created branch exactly
    once (no duplicates across pages), with nextToken exhausted only once all branches are consumed."""
    amplify = ctx.client("amplify")
    app_id = _create_app(ctx)

    branch_names = []
    for _ in range(3):
        branch_name = ctx.unique_name("branch-")
        amplify.create_branch(appId=app_id, branchName=branch_name, tags={"sim2real": "list-branches-pagination"})
        ctx.on_cleanup(lambda b=branch_name: _ignore(lambda: amplify.delete_branch(appId=app_id, branchName=b)))
        branch_names.append(branch_name)

    page1 = amplify.list_branches(appId=app_id, maxResults=2)
    assert len(page1["branches"]) == 2, page1["branches"]
    assert page1.get("nextToken"), "expected a nextToken for the first page"

    all_seen = [b["branchName"] for b in page1["branches"]]
    token = page1["nextToken"]
    pages_left = 5
    while token and pages_left > 0:
        page = amplify.list_branches(appId=app_id, maxResults=2, nextToken=token)
        assert len(page["branches"]) <= 2, page["branches"]
        all_seen.extend(b["branchName"] for b in page["branches"])
        token = page.get("nextToken")
        pages_left -= 1

    assert not token, "pagination did not terminate: nextToken still present after exhausting all created branches"
    assert sorted(all_seen) == sorted(branch_names), (all_seen, branch_names)


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
    app = amplify.create_app(name=name, tags={"sim2real": "list-branches-pagination"})["app"]
    ctx.on_cleanup(lambda: _ignore(lambda: amplify.delete_app(appId=app["appId"])))
    return app["appId"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
