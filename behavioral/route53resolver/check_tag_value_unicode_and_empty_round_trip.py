"""tag-value-unicode-and-empty-round-trip."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-value-unicode-and-empty-round-trip"
GROUP = "representation"
SERVICES = ["route53resolver"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Unicode tag keys and values round-trip exactly through TagResource and ListTagsForResource.

    An empty tag Value is rejected with InvalidParameterException and never appears in a later read.
    """
    r53r = ctx.client("route53resolver")

    resource_arn = r53r.create_firewall_domain_list(
        CreatorRequestId=ctx.unique_name("sim2real-fwdl-tagreq-"),
        Name=ctx.unique_name("sim2real-fwdl-tags-")[:64],
    )["FirewallDomainList"]["Arn"]
    domain_list_id = resource_arn.rsplit("/", 1)[-1]
    ctx.on_cleanup(
        lambda: _safe(lambda: r53r.delete_firewall_domain_list(FirewallDomainListId=domain_list_id))
    )

    unicode_tags = [
        {"Key": "环境-key", "Value": "生产-value"},
        {"Key": "greek-omega-key", "Value": "日本語-value-\u03a9"},
    ]
    r53r.tag_resource(ResourceArn=resource_arn, Tags=unicode_tags)

    listed = r53r.list_tags_for_resource(ResourceArn=resource_arn)["Tags"]
    listed_by_key = {t["Key"]: t["Value"] for t in listed}

    for tag in unicode_tags:
        assert tag["Key"] in listed_by_key, f"tag key {tag['Key']!r} missing from {listed_by_key!r}"
        assert listed_by_key[tag["Key"]] == tag["Value"], (
            f"tag value mismatch for {tag['Key']!r}: "
            f"expected {tag['Value']!r}, got {listed_by_key[tag['Key']]!r}"
        )

    empty_value_key = "empty-value-key"
    refusal = _error(
        lambda: r53r.tag_resource(ResourceArn=resource_arn, Tags=[{"Key": empty_value_key, "Value": ""}])
    )
    expected = (
        "InvalidParameterException",
        "[RSLVR-00908] One of the input parameters of the tags does not meet the acceptance "
        "criteria specified in the restrictions. Please fix the invalid parameter before retrying.",
    )
    assert refusal == expected, f"expected {expected!r} for an empty-string tag Value, got {refusal!r}"

    listed_after = r53r.list_tags_for_resource(ResourceArn=resource_arn)["Tags"]
    listed_by_key_after = {t["Key"]: t["Value"] for t in listed_after}
    assert empty_value_key not in listed_by_key_after, (
        f"rejected empty-value tag {empty_value_key!r} appeared anyway in {listed_by_key_after!r}"
    )
    for tag in unicode_tags:
        assert listed_by_key_after.get(tag["Key"]) == tag["Value"], (
            f"unicode tag {tag['Key']!r} was disturbed by the rejected TagResource call, "
            f"now {listed_by_key_after!r}"
        )


_TRACE_ID = ' Trace Id: "'


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises, with the
    per-request X-Ray trace id suffix removed. A call that succeeds raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        message = err.get("Message", "")
        head, sep, _ = message.rpartition(_TRACE_ID)
        return err.get("Code"), (head if sep and message.endswith('"') else message)
    raise AssertionError(f"expected a ClientError, the call succeeded and returned {result!r}")


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
