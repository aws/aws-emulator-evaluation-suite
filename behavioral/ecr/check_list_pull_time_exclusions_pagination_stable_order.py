"""list-pull-time-exclusions-pagination-stable-order."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-pull-time-exclusions-pagination-stable-order"
GROUP = "ordering"
SERVICES = ["ecr"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:ecr-pull-time-exclusions")
def run(ctx) -> None:
    """ListPullTimeUpdateExclusions returns a stable, consistent relative ordering of
    pre-existing exclusions across paginated calls, even when a new exclusion is
    registered in between page fetches."""
    ecr = ctx.client("ecr")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    created: list[str] = []

    def _cleanup():
        for arn in created:
            try:
                ecr.deregister_pull_time_update_exclusion(principalArn=arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ExclusionNotFoundException":
                    raise

    ctx.on_cleanup(_cleanup)

    baseline_arns = []
    for i in range(6):
        role_name = ctx.unique_name(f"sim2real-ecr-page-{i}-").replace("_", "-")
        arn = f"arn:aws:iam::{account_id}:role/{role_name}"
        ecr.register_pull_time_update_exclusion(principalArn=arn)
        created.append(arn)
        baseline_arns.append(arn)

    # Baseline: a single unpaginated-style listing (large maxResults) order for the set L.
    baseline_order = [
        a for a in _list_all(ecr, max_results=50) if a in baseline_arns
    ]
    assert set(baseline_order) == set(baseline_arns), (
        "baseline unpaginated listing did not return every registered exclusion: "
        f"expected={baseline_arns} got={baseline_order}"
    )

    # Now paginate with a small page size, registering a brand-new exclusion in between
    # page fetches to simulate a mid-pagination mutation.
    paged_order: list[str] = []
    token = None
    first_page = True
    mid_pagination_role = ctx.unique_name("sim2real-ecr-page-mid-").replace("_", "-")
    mid_pagination_arn = f"arn:aws:iam::{account_id}:role/{mid_pagination_role}"
    while True:
        kwargs = {"maxResults": 2}
        if token:
            kwargs["nextToken"] = token
        resp = ecr.list_pull_time_update_exclusions(**kwargs)
        paged_order.extend(resp.get("pullTimeUpdateExclusions", []))

        if first_page:
            ecr.register_pull_time_update_exclusion(principalArn=mid_pagination_arn)
            created.append(mid_pagination_arn)
            first_page = False
        token = resp.get("nextToken")
        if not token:
            break

    filtered_paged_order = [a for a in paged_order if a in baseline_arns]
    assert filtered_paged_order == baseline_order, (
        "pagination did not preserve the relative order of pre-existing exclusions "
        f"despite a mid-pagination insert: baseline={baseline_order} "
        f"paged={filtered_paged_order}"
    )


def _list_all(ecr, max_results: int) -> list[str]:
    out: list[str] = []
    token = None
    while True:
        kwargs = {"maxResults": max_results}
        if token:
            kwargs["nextToken"] = token
        resp = ecr.list_pull_time_update_exclusions(**kwargs)
        out.extend(e for e in resp.get("pullTimeUpdateExclusions", []))

        token = resp.get("nextToken")
        if not token:
            break
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
