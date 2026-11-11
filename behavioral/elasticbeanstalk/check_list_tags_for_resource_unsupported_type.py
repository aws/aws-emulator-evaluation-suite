"""list-tags-for-resource-unsupported-type."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-tags-for-resource-unsupported-type"
GROUP = 'tags'
SERVICES = ['elasticbeanstalk']

def _err(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message) it raises. An unexpected SUCCESS
    raises, because an emulator accepting what real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListTagsForResource on a resource type EB does not support tagging for is rejected distinctly,
    while the identical call against a real, tagged application (the positive control) still
    succeeds before and after."""
    eb = ctx.client("elasticbeanstalk")
    app_name = ctx.unique_name("sim2real-behav-eb-app-unsupported-")
    marker = ctx.unique_name("sim2real-tag-")
    create_resp = eb.create_application(
        ApplicationName=app_name,
        Tags=[{"Key": "sim2real:owner", "Value": marker}],
    )
    app_arn = create_resp["Application"]["ApplicationArn"]
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=True))

    # Positive control: the real application's tags are readable.
    control_tags = {t["Key"]: t["Value"] for t in eb.list_tags_for_resource(ResourceArn=app_arn)["ResourceTags"]}
    assert control_tags.get("sim2real:owner") == marker, (
        f"expected positive control tag 'sim2real:owner'={marker!r}, got {control_tags!r}"
    )

    # Only application, application-version, environment and configuration-template
    # ARNs support tagging; a solution stack / platform-branch style ARN does not.
    unsupported_arn = f"arn:aws:elasticbeanstalk:{ctx.region}::solutionstack/not-a-real-stack"
    code, message = _err(lambda: eb.list_tags_for_resource(ResourceArn=unsupported_arn))
    assert code == "ResourceTypeNotSupportedException", (
        f"expected ResourceTypeNotSupportedException for an "
        f"unsupported resource type, got {code!r}"
    )
    expected_message = (
        f"Tags aren't supported for the resource type of the ARN '{unsupported_arn}'."
    )
    assert message == expected_message, (
        f"expected the exact refusal message {expected_message!r}, got {message!r}"
    )

    # The positive control must still be intact and unaffected by the rejected call.
    recheck_tags = {t["Key"]: t["Value"] for t in eb.list_tags_for_resource(ResourceArn=app_arn)["ResourceTags"]}
    assert recheck_tags.get("sim2real:owner") == marker, (
        f"expected positive control tag 'sim2real:owner'={marker!r} after the rejected call, got {recheck_tags!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
