"""tag-resource-exceeds-limit-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "tag-resource-exceeds-limit-rejected"
GROUP = "negative-classes"
SERVICES = ["swf"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource beyond the 50-tag-per-resource limit is rejected with TooManyTagsFault, not silently truncated."""
    swf = ctx.client("swf")
    domain = ctx.unique_name("sim2real-swf-dom-")
    swf.register_domain(name=domain, workflowExecutionRetentionPeriodInDays="1")
    # SWF has no DeleteDomain: a deprecated domain stays in the account and counts toward its registered-domain quota.
    ctx.on_cleanup(lambda: _safe(lambda: swf.deprecate_domain(name=domain)))
    arn = swf.describe_domain(name=domain)["domainInfo"]["arn"]

    too_many_tags = [{"key": f"sim2real-k{i}", "value": f"v{i}"} for i in range(51)]
    code, message = _error(lambda: swf.tag_resource(resourceArn=arn, tags=too_many_tags))
    assert code == "TooManyTagsFault", f"expected TooManyTagsFault for 51 tags, got {code!r}"
    assert message == "Too many tags provided.", f"unexpected message {message!r}"

    # effect absent: no tags were applied by the rejected call
    tags_after_reject = swf.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags_after_reject == [], f"expected no tags after rejected call, found {tags_after_reject!r}"

    # positive control: a reasonable number of tags is accepted and persisted
    swf.tag_resource(
        resourceArn=arn,
        tags=[{"key": "sim2real-env", "value": "sim2real"}, {"key": "sim2real-team", "value": "qa"}],
    )
    ctx.on_cleanup(
        lambda: _safe(lambda: swf.untag_resource(resourceArn=arn, tagKeys=["sim2real-env", "sim2real-team"]))
    )
    tags_after_accept = {t["key"]: t["value"] for t in swf.list_tags_for_resource(resourceArn=arn)["tags"]}
    expected_accept = {"sim2real-env": "sim2real", "sim2real-team": "qa"}
    assert tags_after_accept == expected_accept, f"expected {expected_accept!r}, got {tags_after_accept!r}"


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("DomainDeprecatedFault", "UnknownResourceFault"):
            raise


def _error(fn):
    """Call fn(); return its botocore Error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected TooManyTagsFault, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
