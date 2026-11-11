"""tag-key-and-value-contract-limits-rejected."""

from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected a rejection, call succeeded with {result!r}")


CHECK = "tag-key-and-value-contract-limits-rejected"
GROUP = 'tagging'
SERVICES = ['config']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource stores a 128-char key and 256-char value byte-exact, and rejects 129/257 chars,
    the reserved aws: prefix and a duplicate key with exact ValidationException messages,
    each refusal leaving the existing tag set untouched.
    """
    cfg = ctx.client("config")
    account = ctx.client("sts").get_caller_identity()["Account"]

    name = ctx.unique_name("sim2real-behav-cfg-aggregator-")
    # An aggregator is taggable without a configuration recorder and has no per-item charge.
    arn = cfg.put_configuration_aggregator(
        ConfigurationAggregatorName=name,
        AccountAggregationSources=[
            {"AccountIds": [account], "AwsRegions": [ctx.region]}
        ],
    )["ConfigurationAggregator"]["ConfigurationAggregatorArn"]
    ctx.on_cleanup(
        lambda n=name: cfg.delete_configuration_aggregator(
            ConfigurationAggregatorName=n
        )
    )

    # Control: the exact modelled maxima must be accepted and stored byte-exact.
    max_key = "k" + "a" * 127
    max_value = "v" + "b" * 255
    assert len(max_key) == 128 and len(max_value) == 256, (
        f"test fixture error: expected a 128-character key and a 256-character value, "
        f"got lengths {len(max_key)} and {len(max_value)}"
    )
    cfg.tag_resource(ResourceArn=arn, Tags=[{"Key": max_key, "Value": max_value}])
    stored = {t["Key"]: t["Value"] for t in cfg.list_tags_for_resource(ResourceArn=arn)["Tags"]}
    assert stored == {max_key: max_value}, (
        f"a 128-character key and 256-character value must round-trip byte-exact and "
        f"be the only tag present; got {stored!r}"
    )
    baseline = dict(stored)

    # botocore does not validate maximum lengths, so these reach the service.
    long_key = "k" + "a" * 128
    long_value = "v" + "b" * 256
    legs = [
        (
            "a tag key one character past the 128-character maximum",
            [{"Key": long_key, "Value": "v"}],
            f"1 validation error detected: Value '{long_key}' at 'tags.1.member.key' "
            "failed to satisfy constraint: Member must have length less than or equal to 128",
        ),
        (
            "a tag value one character past the 256-character maximum",
            [{"Key": "k", "Value": long_value}],
            f"1 validation error detected: Value '{long_value}' at 'tags.1.member.value' "
            "failed to satisfy constraint: Member must have length less than or equal to 256",
        ),
        (
            "a tag key using the reserved aws: prefix",
            [{"Key": "aws:sim2real-behav-cfg-reserved", "Value": "v"}],
            "One or more parameter value is invalid",
        ),
        (
            "the same tag key twice in one call",
            [{"Key": "dupe", "Value": "first"}, {"Key": "dupe", "Value": "second"}],
            "Duplicate tags exists in tags list",
        ),
    ]
    for description, tag_list, expected_message in legs:
        code, message = _error(
            lambda t=tag_list: cfg.tag_resource(ResourceArn=arn, Tags=t)
        )
        assert code == "ValidationException", (
            f"{description} must be refused with ValidationException, never clamped, "
            f"truncated or deduplicated; got {code!r} (message {message!r})"
        )
        assert message == expected_message, (
            f"{description}: the four legs share one error code, so only the message "
            f"tells them apart; expected {expected_message!r}, got {message!r}"
        )
        # Effect absent after EVERY leg: the tag set is exactly the control tag.
        now = {t["Key"]: t["Value"] for t in cfg.list_tags_for_resource(ResourceArn=arn)["Tags"]}
        assert now == baseline, (
            f"{description} was refused but the tag set changed to {now!r} "
            f"(expected {baseline!r}) -- a refused TagResource must be atomic"
        )

    # Control still works: untagging the maximum-length key removes exactly it.
    cfg.untag_resource(ResourceArn=arn, TagKeys=[max_key])
    assert cfg.list_tags_for_resource(ResourceArn=arn)["Tags"] == [], (
        "UntagResource on the 128-character key must remove exactly that key"
    )

    # ...and a key that was never accepted must not be removable either, so the
    # refusals above really did leave no shadow state behind.
    cfg.untag_resource(ResourceArn=arn, TagKeys=["dupe"])
    assert cfg.list_tags_for_resource(ResourceArn=arn)["Tags"] == [], (
        "no tag from a refused call may be present"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
