"""create-activity-forbidden-character-in-name-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-activity-forbidden-character-in-name-rejected"
GROUP = "activities"
SERVICES = ["stepfunctions"]


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected
    SUCCESS raises, naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected CreateActivity to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateActivity with a wildcard character in the name fails with InvalidName and the
    exact message and creates nothing, while the same name with the character stripped
    succeeds and is describable."""
    sfn = ctx.client("stepfunctions")
    prefix = ctx.unique_name("sim2real-behav-act-")

    bad_name = f"{prefix}wild*card"
    code, message = _error(lambda: sfn.create_activity(name=bad_name))
    assert code == "InvalidName", f"expected InvalidName, got {code!r}: {message!r}"
    expected = f"Invalid Name: '{bad_name}'"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    paginator = sfn.get_paginator("list_activities")
    names = {a["name"] for page in paginator.paginate() for a in page["activities"]}
    assert bad_name not in names, f"a refused activity named {bad_name!r} is listed"

    good_name = f"{prefix}wildcard"
    good_arn = sfn.create_activity(name=good_name)["activityArn"]
    ctx.on_cleanup(lambda: sfn.delete_activity(activityArn=good_arn))
    described = sfn.describe_activity(activityArn=good_arn)
    assert described["name"] == good_name, (
        f"DescribeActivity returned name {described['name']!r}, expected {good_name!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
