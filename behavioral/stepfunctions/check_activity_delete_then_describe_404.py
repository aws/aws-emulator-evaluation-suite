"""activity-delete-then-describe-404."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "activity-delete-then-describe-404"
GROUP = 'activities'
SERVICES = ['stepfunctions']


def _create_activity(ctx, *, name=None):
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-act-")
    arn = sfn.create_activity(name=name, tags=[{"key": "sim2real", "value": "1"}])["activityArn"]
    ctx.on_cleanup(lambda: sfn.delete_activity(activityArn=arn))
    return {"name": name, "arn": arn}


def _error(fn):
    """Call fn(); return its error as {"Code", "Message"}. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return {"Code": err.get("Code"), "Message": err.get("Message")}
    raise AssertionError(f"expected the call to fail, but it succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Describing a deleted activity yields ActivityDoesNotExist, and the freed name is
    immediately reusable by a fresh CreateActivity."""
    sfn = ctx.client("stepfunctions")
    act = _create_activity(ctx)

    # positive control: the activity is describable while it still exists
    sfn.describe_activity(activityArn=act["arn"])

    sfn.delete_activity(activityArn=act["arn"])
    # resource deleted by the check; cleanup is idempotent/best-effort

    err = _error(lambda: sfn.describe_activity(activityArn=act["arn"]))
    expected = {"Code": "ActivityDoesNotExist", "Message": f"Activity Does Not Exist: '{act['arn']}'"}
    assert err == expected, f"DescribeActivity on a deleted activity: expected {expected}, got {err}"

    # the freed name must be reusable, not left in limbo by a lingering tombstone. An
    # activity's ARN is derived from its name (account+region+name), not a random id, so
    # the recreated activity gets back the identical ARN.
    reused = _create_activity(ctx, name=act["name"])
    assert reused["arn"] == act["arn"], (
        f"recreating {act['name']!r} after delete returned a different ARN: "
        f"expected {act['arn']!r}, got {reused['arn']!r}"
    )
    sfn.describe_activity(activityArn=reused["arn"])


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
