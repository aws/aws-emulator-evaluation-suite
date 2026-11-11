"""tag-resource-quota-exceeded-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-quota-exceeded-rejected"
GROUP = "server-side"
SERVICES = ["bedrock"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource pushing a policy holding 5 tags past the per-resource quota returns
    TooManyTagsException 'You can assign a maximum of 50 tags to a resource' and keeps exactly the 5
    prior tags, while a 3-tag call afterwards brings it to 8."""
    bedrock = ctx.client("bedrock")
    name = ctx.unique_name("sim2real-behav-tagquota-")
    created = bedrock.create_automated_reasoning_policy(name=name)
    policy_arn = created["policyArn"]
    ctx.on_cleanup(lambda: bedrock.delete_automated_reasoning_policy(policyArn=policy_arn))

    # Positive control: a small, within-quota batch of tags is accepted.
    initial_tags = [{"key": f"sim2real-quota-k{i}", "value": f"v{i}"} for i in range(5)]
    bedrock.tag_resource(resourceARN=policy_arn, tags=initial_tags)
    after_initial = bedrock.list_tags_for_resource(resourceARN=policy_arn)["tags"]
    assert len(after_initial) == 5, f"expected 5 tags after positive control, got {after_initial!r}"

    # Break exactly one thing: push the resource's total tag count far past any
    # per-resource quota (5 existing + 197 new = 202).
    overflow_tags = [{"key": f"sim2real-quota-overflow{i}", "value": f"v{i}"} for i in range(197)]

    code, message = _error(lambda: bedrock.tag_resource(resourceARN=policy_arn, tags=overflow_tags))
    assert code == "TooManyTagsException", f"expected TooManyTagsException, got {code!r}"
    assert message == "You can assign a maximum of 50 tags to a resource", (
        f"unexpected TooManyTagsException message {message!r}"
    )

    # The rejected batch must not have been partially applied.
    remaining = bedrock.list_tags_for_resource(resourceARN=policy_arn)["tags"]
    assert len(remaining) == 5, f"expected the prior 5 tags to survive the rejected call, got {remaining!r}"
    assert {t["key"] for t in remaining} == {t["key"] for t in initial_tags}, (
        f"expected exactly the prior tag keys to survive, got {sorted(t['key'] for t in remaining)!r}"
    )

    # Restore: the same resource still accepts a within-quota TagResource call afterward.
    extra_tags = [{"key": f"sim2real-quota-extra{i}", "value": f"v{i}"} for i in range(3)]
    bedrock.tag_resource(resourceARN=policy_arn, tags=extra_tags)
    after_extra = bedrock.list_tags_for_resource(resourceARN=policy_arn)["tags"]
    assert len(after_extra) == 8, f"expected 8 tags after the within-quota restore call, got {after_extra!r}"
    assert {t["key"] for t in extra_tags} <= {t["key"] for t in after_extra}, (
        f"expected the new within-quota tags to be applied, got {sorted(t['key'] for t in after_extra)!r}"
    )


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
