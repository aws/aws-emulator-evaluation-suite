"""foreign-resource-arn-for-tagging-rejected."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags

CHECK = "foreign-resource-arn-for-tagging-rejected"
GROUP = "overly-permissive"
SERVICES = ["elasticbeanstalk"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateTagsForResource and ListTagsForResource both reject a non-Elastic-Beanstalk resource ARN
    with InvalidParameterValue, while a genuine EB application ARN still tags successfully."""
    eb = ctx.client("elasticbeanstalk")
    sts = ctx.client("sts")

    account_id = sts.get_caller_identity()["Account"]
    foreign_arn = f"arn:aws:sns:{ctx.region}:{account_id}:{ctx.unique_name('sim2real-not-eb-')}"

    write_code, write_message = _error_code(
        lambda: eb.update_tags_for_resource(
            ResourceArn=foreign_arn, TagsToAdd=[{"Key": "sim2real-k", "Value": "v"}]
        )
    )
    assert write_code == "InvalidParameterValue", (
        f"expected InvalidParameterValue for UpdateTagsForResource on a foreign ARN, got {write_code!r}"
    )
    expected_message = f"The name '{foreign_arn}' isn't a valid ARN of an Elastic Beanstalk resource."
    assert write_message == expected_message, (
        f"expected the exact refusal message {expected_message!r}, got {write_message!r}"
    )

    read_code, read_message = _error_code(lambda: eb.list_tags_for_resource(ResourceArn=foreign_arn))
    assert read_code == "InvalidParameterValue", (
        f"expected InvalidParameterValue for ListTagsForResource on a foreign ARN, got {read_code!r}"
    )
    expected_message = f"The name '{foreign_arn}' isn't a valid ARN of an Elastic Beanstalk resource."
    assert read_message == expected_message, (
        f"expected the exact refusal message {expected_message!r}, got {read_message!r}"
    )

    # positive control: a genuine Elastic Beanstalk application ARN tags successfully
    app_name = ctx.unique_name("sim2real-eb-app-")
    app_arn = eb.create_application(ApplicationName=app_name)["Application"]["ApplicationArn"]
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=app_name))

    eb.update_tags_for_resource(ResourceArn=app_arn, TagsToAdd=[{"Key": "sim2real-control", "Value": "ok"}])
    tags_now = {t["Key"]: t["Value"] for t in eb.list_tags_for_resource(ResourceArn=app_arn)["ResourceTags"]}
    assert tags_now.get("sim2real-control") == "ok", f"positive-control tag did not persist: {tags_now}"


def _error_code(fn: Callable[[], Any]):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
