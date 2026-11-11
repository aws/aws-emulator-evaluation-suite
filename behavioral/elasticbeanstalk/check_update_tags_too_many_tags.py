"""update-tags-too-many-tags."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-tags-too-many-tags"
GROUP = 'tags'
SERVICES = ['elasticbeanstalk']

def _error_code(fn):
    """Call fn(); return its botocore (Error.Code, Error.Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _tags_of(eb, resource_arn):
    resp = eb.list_tags_for_resource(ResourceArn=resource_arn)
    return {t["Key"]: t["Value"] for t in resp["ResourceTags"]}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateTagsForResource past the 50-tag limit fails with TooManyTagsException and the exact message and leaves
    the tag set unchanged, while an in-quota addition on the same resource persists."""
    eb = ctx.client("elasticbeanstalk")
    app_name = ctx.unique_name("sim2real-behav-eb-app-")
    resp = eb.create_application(ApplicationName=app_name)
    ctx.on_cleanup(lambda _n=app_name: eb.delete_application(ApplicationName=_n, TerminateEnvByForce=True))
    app_arn = resp["Application"]["ApplicationArn"]

    baseline = _tags_of(eb, app_arn)

    too_many_tags = [{"Key": f"sim2real-tag-{i}", "Value": str(i)} for i in range(51)]
    code, message = _error_code(
        lambda: eb.update_tags_for_resource(ResourceArn=app_arn, TagsToAdd=too_many_tags)
    )
    assert code == "TooManyTagsException", (
        f"expected TooManyTagsException when exceeding the 50-tag-per-resource limit, got {code!r}"
    )
    expected_message = "The maximum number of tags per resource is exceeded. The number of allowed tags is 50."
    assert message == expected_message, (
        f"expected the exact refusal message {expected_message!r}, got {message!r}"
    )

    after_reject = _tags_of(eb, app_arn)
    assert after_reject == baseline, (
        f"tags leaked onto the resource despite the quota rejection: {after_reject} != {baseline}"
    )

    # positive control: a modest, in-quota addition on the same resource still succeeds
    eb.update_tags_for_resource(ResourceArn=app_arn, TagsToAdd=[{"Key": "sim2real-control", "Value": "ok"}])
    after_control = _tags_of(eb, app_arn)
    assert after_control.get("sim2real-control") == "ok", (
        f"positive-control tag addition did not persist: {after_control}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
