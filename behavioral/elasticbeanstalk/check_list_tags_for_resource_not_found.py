"""list-tags-for-resource-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-tags-for-resource-not-found"
GROUP = 'tags'
SERVICES = ['elasticbeanstalk']


def _err(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message) if it raises. An unexpected SUCCESS
    raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListTagsForResource on an in-account ARN with no backing EB resource fails distinctly,
    while the same call against a real, tagged application (the positive control) keeps
    succeeding before and after the rejected call."""
    eb = ctx.client("elasticbeanstalk")
    app_name = ctx.unique_name("sim2real-behav-eb-app-acct-")
    marker = {"Key": "sim2real:owner", "Value": "behavioral-check"}
    arn = eb.create_application(ApplicationName=app_name, Tags=[marker])["Application"]["ApplicationArn"]
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=True))
    account = arn.split(":")[4]

    # Positive control: the real application's tags are readable.
    control_tags = {t["Key"]: t["Value"] for t in eb.list_tags_for_resource(ResourceArn=arn)["ResourceTags"]}
    assert control_tags.get("sim2real:owner") == "behavioral-check", (
        f"positive control: expected tag sim2real:owner=behavioral-check on {arn}, got {control_tags!r}"
    )

    # Break exactly one thing: point at an application ARN with the same account/region/format
    # that was never created.
    bogus_arn = (
        f"arn:aws:elasticbeanstalk:{ctx.region}:{account}:application/"
        f"{ctx.unique_name('sim2real-behav-no-such-app-')}"
    )
    code, message = _err(lambda: eb.list_tags_for_resource(ResourceArn=bogus_arn))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a nonexistent resource ARN {bogus_arn}, got {code!r}"
    )
    expected_message = f"Resource not found for ARN '{bogus_arn}'."
    assert message == expected_message, (
        f"expected the exact refusal message {expected_message!r}, got {message!r}"
    )

    # The positive control must still be intact and unaffected by the failed call.
    recheck_tags = {t["Key"]: t["Value"] for t in eb.list_tags_for_resource(ResourceArn=arn)["ResourceTags"]}
    assert recheck_tags.get("sim2real:owner") == "behavioral-check", (
        f"post-rejection recheck: expected tag sim2real:owner=behavioral-check on {arn} to survive "
        f"the failed call against {bogus_arn}, got {recheck_tags!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
