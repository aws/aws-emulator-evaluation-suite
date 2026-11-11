"""update-tags-for-resource-quota-exceeded-rejected."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "update-tags-for-resource-quota-exceeded-rejected"
GROUP = "overly-permissive"
SERVICES = ["elasticbeanstalk"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx: Any) -> None:
    """UpdateTagsForResource rejects a batch that would push a resource over the 50-tag
    quota (TooManyTags), leaves the resource's tag set unchanged, and a modest, in-quota
    tag addition on the same resource still succeeds (positive control)."""
    eb = ctx.client("elasticbeanstalk")
    app_name = ctx.unique_name("sim2real-eb-app-")

    app = eb.create_application(
        ApplicationName=app_name, Tags=[{"Key": "sim2real", "Value": "true"}]
    )["Application"]
    app_arn = app["ApplicationArn"]
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=app_name))

    baseline = _tags_of(ctx, app_arn)

    too_many = [{"Key": f"sim2real-quota-{i}", "Value": str(i)} for i in range(60)]
    code, message = _error_code(lambda: eb.update_tags_for_resource(ResourceArn=app_arn, TagsToAdd=too_many))
    assert code == "TooManyTagsException", f"expected TooManyTagsException, got {code!r}"
    expected_message = "The maximum number of tags per resource is exceeded. The number of allowed tags is 50."
    assert message == expected_message, (
        f"expected the exact refusal message {expected_message!r}, got {message!r}"
    )

    after_failed_attempt = _tags_of(ctx, app_arn)
    assert after_failed_attempt == baseline, (
        f"tag set changed despite rejected over-quota request: {after_failed_attempt} != {baseline}"
    )

    # positive control: a small, in-quota addition on the same resource succeeds
    eb.update_tags_for_resource(
        ResourceArn=app_arn, TagsToAdd=[{"Key": "sim2real-control", "Value": "ok"}]
    )
    after_control = _tags_of(ctx, app_arn)
    assert after_control.get("sim2real-control") == "ok", (
        f"positive-control tag addition did not persist: {after_control}"
    )


def _tags_of(ctx: Any, resource_arn: str) -> dict[str, str]:
    eb = ctx.client("elasticbeanstalk")
    resp = eb.list_tags_for_resource(ResourceArn=resource_arn)
    return {t["Key"]: t["Value"] for t in resp["ResourceTags"]}


def _error_code(fn: Any) -> tuple[str, str | None]:
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
