"""authorizer-tag-untag-round-trip-and-missing-authorizer-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "authorizer-tag-untag-round-trip-and-missing-authorizer-rejected"
GROUP = 'overly-permissive'
SERVICES = ['iot']


def _err(fn):
    """Call fn(); return the ClientError (code, message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tags on an authorizer ARN round-trip across independent TagResource/UntagResource reads.

    On a nonexistent authorizer ARN, ListTagsForResource reads empty while TagResource 404s.
    """
    iot = ctx.client("iot")
    account = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-behav-authztags-")
    fn_arn = f"arn:aws:lambda:{ctx.region}:{account}:function:sim2real-behav-authztags-fn"

    iot.create_authorizer(authorizerName=name, authorizerFunctionArn=fn_arn, signingDisabled=True)
    ctx.on_cleanup(lambda: iot.delete_authorizer(authorizerName=name))
    ctx.on_cleanup(lambda: iot.update_authorizer(authorizerName=name, status="INACTIVE"))

    arn = iot.describe_authorizer(authorizerName=name)["authorizerDescription"]["authorizerArn"]

    iot.tag_resource(resourceArn=arn, tags=[{"Key": "env", "Value": "dev"}, {"Key": "team", "Value": "a"}])
    first_read = {t["Key"]: t["Value"] for t in iot.list_tags_for_resource(resourceArn=arn)["tags"]}
    assert first_read == {"env": "dev", "team": "a"}, (
        f"expected {{'env': 'dev', 'team': 'a'}} after tag_resource, got {first_read!r}"
    )

    # A later, independent read sees a tag added by a prior write, including an overwrite.
    iot.tag_resource(resourceArn=arn, tags=[{"Key": "team", "Value": "b"}, {"Key": "owner", "Value": "x"}])
    second_read = {t["Key"]: t["Value"] for t in iot.list_tags_for_resource(resourceArn=arn)["tags"]}
    assert second_read == {"env": "dev", "team": "b", "owner": "x"}, (
        f"expected team overwritten and owner added, got {second_read!r}"
    )

    iot.untag_resource(resourceArn=arn, tagKeys=["env"])
    third_read = {t["Key"]: t["Value"] for t in iot.list_tags_for_resource(resourceArn=arn)["tags"]}
    assert third_read == {"team": "b", "owner": "x"}, (
        f"expected 'env' removed and the rest intact, got {third_read!r}"
    )

    # An authorizer that was never created.
    missing_name = ctx.unique_name("sim2real-behav-authztags-missing-")
    missing_arn = f"arn:aws:iot:{ctx.region}:{account}:authorizer/{missing_name}"

    missing_read = iot.list_tags_for_resource(resourceArn=missing_arn)["tags"]
    assert missing_read == [], (
        f"ListTagsForResource on a nonexistent authorizer must read back empty, got {missing_read!r}"
    )

    code, message = _err(
        lambda: iot.tag_resource(resourceArn=missing_arn, tags=[{"Key": "k", "Value": "v"}]))
    expected = f"Authorizer {missing_name} not found"
    assert (code, message) == ("ResourceNotFoundException", expected), (
        f"TagResource on a nonexistent authorizer must 404 with {expected!r}, got {code!r}: "
        f"{message!r}"
    )
    # The rejected write must not have created anything a later read could see.
    missing_read_after = iot.list_tags_for_resource(resourceArn=missing_arn)["tags"]
    assert missing_read_after == [], (
        f"the rejected tag_resource must leave the read empty, got {missing_read_after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
