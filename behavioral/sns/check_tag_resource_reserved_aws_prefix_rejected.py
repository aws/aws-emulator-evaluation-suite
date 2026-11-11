"""tag-resource-reserved-aws-prefix-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-reserved-aws-prefix-rejected"
GROUP = 'tagging'
SERVICES = ['sns']


def _error(fn):
    """Return (Error.Code, Error.Message) of the ClientError fn raises; a success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _tags(sns, arn):
    return {t["Key"]: t["Value"] for t in sns.list_tags_for_resource(ResourceArn=arn)["Tags"]}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource refuses a key in the reserved `aws:` namespace and applies nothing from
    that request -- not even its legal sibling tag -- while the sibling alone is accepted.
    """
    sns = ctx.client("sns")
    arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-behav-sns-awstag-"),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))

    code, message = _error(lambda: sns.tag_resource(
        ResourceArn=arn,
        Tags=[{"Key": "aws:reserved", "Value": "x"}, {"Key": "legal", "Value": "y"}],
    ))
    assert code == "InvalidParameter", f"TagResource with an aws: key gave {code!r}"
    assert message == "Invalid parameter: Tags Reason: Caller is an end user and not allowed to mutate system tags", f"unexpected message for an aws: tag key: {message!r}"
    assert _tags(sns, arn) == {"sim2real": CHECK}, (
        f"the refused TagResource must apply nothing, got {_tags(sns, arn)!r}"
    )

    sns.tag_resource(ResourceArn=arn, Tags=[{"Key": "legal", "Value": "y"}])
    assert _tags(sns, arn) == {"sim2real": CHECK, "legal": "y"}, (
        f"the legal tag alone must be accepted, got {_tags(sns, arn)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
