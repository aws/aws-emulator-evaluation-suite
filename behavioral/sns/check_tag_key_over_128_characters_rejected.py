"""tag-key-over-128-characters-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-key-over-128-characters-rejected"
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
    """TagResource refuses a 129-character tag key and stores nothing from that request,
    while a 128-character key -- the documented maximum -- is accepted and read back.
    """
    sns = ctx.client("sns")
    arn = sns.create_topic(Name=ctx.unique_name("sim2real-behav-sns-longkey-"),
                           Tags=[{"Key": "sim2real", "Value": CHECK}])["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    too_long, at_limit = "k" * 129, "k" * 128

    code, message = _error(lambda: sns.tag_resource(ResourceArn=arn, Tags=[{"Key": too_long, "Value": "v"}]))
    # SNS answers ValidationError here, a code its API model does not declare for TagResource.
    assert code == "ValidationError", f"a 129-character tag key gave {code!r}"
    expected = (f"1 validation error detected: Value '{too_long}' at 'tags.1.member.key' failed "
                "to satisfy constraint: Member must have length less than or equal to 128")
    assert message == expected, f"unexpected message for a 129-character tag key: {message!r}"
    assert _tags(sns, arn) == {"sim2real": CHECK}, "the refused TagResource must store nothing"

    sns.tag_resource(ResourceArn=arn, Tags=[{"Key": at_limit, "Value": "v"}])
    assert _tags(sns, arn) == {"sim2real": CHECK, at_limit: "v"}, "a 128-character tag key must be stored"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
