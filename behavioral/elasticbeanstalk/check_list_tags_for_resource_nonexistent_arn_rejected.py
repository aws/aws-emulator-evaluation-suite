"""list-tags-for-resource-nonexistent-arn-rejected."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags

CHECK = "list-tags-for-resource-nonexistent-arn-rejected"
GROUP = "representation"
SERVICES = ["elasticbeanstalk"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListTagsForResource on a well-formed ARN of a nonexistent application fails with ResourceNotFoundException and
    the exact message, while a real tagged application returns its tag before and after the refusal."""
    eb = ctx.client("elasticbeanstalk")
    app_name = ctx.unique_name("sim2real-eb-app-")

    tags = [{"Key": "sim2real:owner", "Value": "behavioral-check"}]
    create_resp = eb.create_application(ApplicationName=app_name, Tags=tags)
    app_arn = create_resp["Application"]["ApplicationArn"]
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=app_name))

    # Positive control: the real application's tags are readable.
    control_tags = eb.list_tags_for_resource(ResourceArn=app_arn)["ResourceTags"]
    control_map = {t["Key"]: t["Value"] for t in control_tags}
    assert control_map.get("sim2real:owner") == "behavioral-check", (
        f"positive control: expected tag sim2real:owner=behavioral-check on {app_arn}, "
        f"got {control_map!r}"
    )

    # Break exactly one thing: point at an application ARN with the same
    # account/region/format that was never created.
    bogus_name = ctx.unique_name("sim2real-eb-missing-")
    bogus_arn = app_arn.rsplit(":application/", 1)[0] + f":application/{bogus_name}"
    assert bogus_arn != app_arn, f"bogus ARN collided with the real one: {bogus_arn}"

    code, message = _error_code(lambda: eb.list_tags_for_resource(ResourceArn=bogus_arn))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for nonexistent ARN {bogus_arn}, got {code!r}"
    )
    expected = f"Resource not found for ARN '{bogus_arn}'."
    assert message == expected, (
        f"expected {expected!r} for nonexistent ARN {bogus_arn}, got {message!r}"
    )

    # The positive control must still be intact and unaffected by the failed call.
    recheck_tags = eb.list_tags_for_resource(ResourceArn=app_arn)["ResourceTags"]
    recheck_map = {t["Key"]: t["Value"] for t in recheck_tags}
    assert recheck_map.get("sim2real:owner") == "behavioral-check", (
        f"post-rejection recheck: expected tag sim2real:owner=behavioral-check on {app_arn} "
        f"to survive the failed call against {bogus_arn}, got {recheck_map!r}"
    )


def _error_code(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn(); return (Error.Code, Error.Message) if it raises. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
