"""tag-resource-reserved-aws-prefix-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-reserved-aws-prefix-rejected"
GROUP = "representation"
SERVICES = ["wafv2"]


_RESERVED_TAG_MESSAGE = (
    "You tried to tag your resources with system tag keys. These tags have an aws: prefix "
    "and are reserved by AWS. Change your tag keys, and try again."
)

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource rejects an 'aws:'-prefixed tag key with WAFTagOperationException and the tag
    is not stored, while a valid non-reserved key (positive control) is accepted and listed."""
    wafv2 = ctx.client("wafv2")
    name = ctx.unique_name("sim2real-ipset-tagneg-")
    created = wafv2.create_ip_set(
        Name=name,
        Scope="REGIONAL",
        IPAddressVersion="IPV4",
        Addresses=["203.0.113.0/24"],
    )["Summary"]
    ip_set_id = created["Id"]
    arn = created["ARN"]

    def _cleanup():
        current = wafv2.get_ip_set(Name=name, Scope="REGIONAL", Id=ip_set_id)
        wafv2.delete_ip_set(
            Name=name, Scope="REGIONAL", Id=ip_set_id, LockToken=current["LockToken"]
        )

    ctx.on_cleanup(_cleanup)

    code, message = _error_code(
        lambda: wafv2.tag_resource(
            ResourceARN=arn, Tags=[{"Key": "aws:Reserved", "Value": "x"}]
        )
    )
    assert code == "WAFTagOperationException", f"expected WAFTagOperationException, got {code}"
    assert message == _RESERVED_TAG_MESSAGE, message

    tags = wafv2.list_tags_for_resource(ResourceARN=arn)["TagInfoForResource"].get("TagList", [])
    assert all(t["Key"] != "aws:Reserved" for t in tags), (
        f"expected no 'aws:Reserved' tag on {arn}, found it in {tags}"
    )

    # Positive control: a valid, non-reserved key is accepted and shows up on read.
    wafv2.tag_resource(ResourceARN=arn, Tags=[{"Key": "Team", "Value": "sim2real"}])
    tags_after = wafv2.list_tags_for_resource(ResourceARN=arn)["TagInfoForResource"]["TagList"]
    matching = [t for t in tags_after if t["Key"] == "Team"]
    assert len(matching) == 1 and matching[0]["Value"] == "sim2real", (
        f"expected exactly one 'Team'='sim2real' tag, found {tags_after}"
    )


def _error_code(fn):
    """Call fn(); return its (code, message). An unexpected success raises, so acceptance
    never reads as an error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
