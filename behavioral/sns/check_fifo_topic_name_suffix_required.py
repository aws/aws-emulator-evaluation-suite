"""fifo-topic-name-suffix-required."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "fifo-topic-name-suffix-required"
GROUP = 'overly-permissive'
SERVICES = ['sns']

_SCENARIO = "sns-fifo-topic-name-suffix"


def _error(fn):
    """Call fn(); return (code, message) of the ClientError it raises. An unexpected success
    raises, so a target that accepts what AWS refuses never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": "sim2real", "Value": _SCENARIO}, {"Key": "sim2real:managed", "Value": "true"}]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Creating a FIFO topic (Attributes.FifoTopic=true) without a .fifo name suffix must fail."""
    sns = ctx.client("sns")

    # Positive control: a correctly-suffixed FIFO topic must succeed, so the rejection
    # below is attributable to the missing suffix and not to FIFO being unavailable at all.
    good_name = ctx.unique_name("sim2real-behav-sns-fifo-good-") + ".fifo"
    good_arn = sns.create_topic(
        Name=good_name, Attributes={'FifoTopic': 'true'}, Tags=_tags_kv()
    )["TopicArn"]
    ctx.on_cleanup(lambda a=good_arn: sns.delete_topic(TopicArn=a))
    assert good_arn.endswith(good_name), (
        f"expected the positive-control FIFO topic ARN to echo {good_name!r}, got {good_arn}"
    )

    bad_name = ctx.unique_name("sim2real-behav-sns-fifo-bad-")
    code, message = _error(lambda: sns.create_topic(Name=bad_name, Attributes={'FifoTopic': 'true'}))
    assert code == "InvalidParameter", (
        f"expected InvalidParameter for FIFO topic missing .fifo suffix, got {code}"
    )
    expected = 'Invalid parameter: Topic Name'
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the rejected topic must not have been created at the destination.
    arns = [t["TopicArn"] for t in sns.list_topics().get("Topics", [])]
    assert not any(a.endswith(f":{bad_name}") for a in arns), (
        f"rejected FIFO topic {bad_name!r} must not appear in ListTopics, saw {arns}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
