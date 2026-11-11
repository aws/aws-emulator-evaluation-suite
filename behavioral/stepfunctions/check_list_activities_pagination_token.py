"""list-activities-pagination-token."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-activities-pagination-token"
GROUP = 'activities'
SERVICES = ['stepfunctions']


def _create_activity(ctx, *, name=None):
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-act-")
    arn = sfn.create_activity(name=name, tags=[{"key": "sim2real", "value": "1"}])["activityArn"]
    ctx.on_cleanup(lambda: sfn.delete_activity(activityArn=arn))
    return {"name": name, "arn": arn}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListActivities paginates consistently using nextToken, with no duplicates or drops."""
    sfn = ctx.client("stepfunctions")
    created_arns = set()
    for i in range(3):
        act = _create_activity(ctx, name=ctx.unique_name(f"sim2real-behav-act-page-{i}-"))
        created_arns.add(act["arn"])

    seen_arns: list[str] = []
    next_token = None
    pages = 0
    while True:
        kwargs: dict = {"maxResults": 1}
        if next_token:
            kwargs["nextToken"] = next_token
        resp = sfn.list_activities(**kwargs)
        pages += 1
        seen_arns.extend(a["activityArn"] for a in resp["activities"])
        next_token = resp.get("nextToken")
        if not next_token or pages > 500:
            break

    assert len(seen_arns) == len(set(seen_arns)), "pagination must not return duplicate activities"
    seen_set = set(seen_arns)
    missing = created_arns - seen_set
    assert not missing, f"pagination must surface every created activity, missing: {missing}"
    assert pages >= 3, f"expected at least 3 pages with maxResults=1 and >=3 activities, got {pages}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
