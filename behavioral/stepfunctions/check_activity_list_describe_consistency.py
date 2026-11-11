"""activity-list-describe-consistency."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "activity-list-describe-consistency"
GROUP = "state-machine"
SERVICES = ["stepfunctions"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A newly created activity immediately appears in ListActivities and its
    fields match DescribeActivity."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-activity-")
    activity_arn = sfn.create_activity(name=name)["activityArn"]
    ctx.on_cleanup(lambda: _swallow(lambda: sfn.delete_activity(activityArn=activity_arn)))

    described = sfn.describe_activity(activityArn=activity_arn)
    assert described["name"] == name, f"expected name {name!r}, DescribeActivity returned {described['name']!r}"
    assert described["activityArn"] == activity_arn, (
        f"expected activityArn {activity_arn!r}, DescribeActivity returned {described['activityArn']!r}"
    )
    assert "creationDate" in described, f"DescribeActivity response missing creationDate: {described!r}"

    found = None
    next_token = None
    while True:
        kwargs = {"nextToken": next_token} if next_token else {}
        page = sfn.list_activities(**kwargs)
        for a in page["activities"]:
            if a["activityArn"] == activity_arn:
                found = a
                break
        if found is not None:
            break
        next_token = page.get("nextToken")
        if not next_token:
            break

    assert found is not None, f"activity {activity_arn} not found via ListActivities"
    assert found["name"] == described["name"], (
        f"ListActivities name {found['name']!r} != DescribeActivity name {described['name']!r}"
    )
    assert found["creationDate"] == described["creationDate"], (
        f"ListActivities creationDate {found['creationDate']!r} != "
        f"DescribeActivity creationDate {described['creationDate']!r}"
    )


def _swallow(fn):
    fn()


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
