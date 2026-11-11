"""tag-resource-too-many-tags-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-too-many-tags-rejected"
GROUP = "negative-classes"
SERVICES = ["swf"]

_MAX_TAGS_PER_RESOURCE = 50


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource is rejected with TooManyTagsFault once the 50-tag-per-resource limit would be exceeded, and the
    previously-applied tags remain unchanged."""
    swf = ctx.client("swf")
    domain = ctx.unique_name("sim2real-behav-domain-")
    initial_tags = [{"key": "seed-a", "value": "1"}, {"key": "seed-b", "value": "2"}]
    swf.register_domain(
        name=domain, workflowExecutionRetentionPeriodInDays="1", tags=initial_tags
    )
    ctx.on_cleanup(lambda: _best_effort_deprecate(swf, domain))

    arn = swf.describe_domain(name=domain)["domainInfo"]["arn"]
    tags_before = _tag_map(swf, arn)
    assert tags_before == {"seed-a": "1", "seed-b": "2"}, f"expected seed tags only, got {tags_before!r}"

    # Pushing total tags past the 50-per-resource limit must be rejected outright.
    overflow_count = _MAX_TAGS_PER_RESOURCE - len(initial_tags) + 1
    overflow_tags = [{"key": f"overflow-{i}", "value": str(i)} for i in range(overflow_count)]
    code, message = _error(lambda: swf.tag_resource(resourceArn=arn, tags=overflow_tags))
    assert code == "TooManyTagsFault", f"expected TooManyTagsFault, got {code!r}"
    assert message == "Too many tags provided.", f"unexpected message {message!r}"

    # Effect absent: the resource still carries exactly the original two tags.
    tags_after = _tag_map(swf, arn)
    assert tags_after == {"seed-a": "1", "seed-b": "2"}, f"expected rejected call to leave tags unchanged, got {tags_after!r}"

    # Positive control: a small, well-within-limit tag addition succeeds and is visible.
    swf.tag_resource(resourceArn=arn, tags=[{"key": "seed-c", "value": "3"}])
    tags_control = _tag_map(swf, arn)
    assert tags_control == {"seed-a": "1", "seed-b": "2", "seed-c": "3"}, f"expected control tag to be visible, got {tags_control!r}"


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _tag_map(swf, arn):
    tag_list = swf.list_tags_for_resource(resourceArn=arn)["tags"]
    return {t["key"]: t["value"] for t in tag_list}


def _best_effort_deprecate(swf, name):
    try:
        # SWF has no DeleteDomain: a deprecated domain stays in the account and counts toward its registered-domain quota.
        swf.deprecate_domain(name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("DomainDeprecatedFault", "UnknownResourceFault"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
