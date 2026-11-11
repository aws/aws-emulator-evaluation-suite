"""tag-resource-quota-exceeded-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-quota-exceeded-rejected"
GROUP = "error-semantics"
SERVICES = ["codeartifact"]


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource rejects a request that would push a resource's tag count past the
    per-resource tag quota (50, empirically) with ServiceQuotaExceededException, and
    the resource's tag set is left exactly as it was before the attempt."""
    ca = ctx.client("codeartifact")
    domain = (ctx.unique_name("sim2real-ca-") + "0").lower()
    created = ca.create_domain(domain=domain)["domain"]
    ctx.on_cleanup(lambda: ca.delete_domain(domain=domain))
    resource_arn = created["arn"]

    # Fill the resource up to exactly the 50-tag quota.
    quota = 50
    full_tags = [{"key": f"sim2real-k{i}", "value": f"v{i}"} for i in range(quota)]
    ca.tag_resource(resourceArn=resource_arn, tags=full_tags)
    ctx.on_cleanup(
        lambda: ca.untag_resource(resourceArn=resource_arn, tagKeys=[t["key"] for t in full_tags])
    )

    current = ca.list_tags_for_resource(resourceArn=resource_arn)["tags"]
    assert len(current) == quota, f"expected {quota} tags after filling to quota, got {len(current)}"

    # Attempting to add one more (new, distinct) tag would push the total to 51.
    extra_tag = {"key": "sim2real-extra-tag", "value": "overflow"}
    code, message = _error(lambda: ca.tag_resource(resourceArn=resource_arn, tags=[extra_tag]))
    assert code == "ServiceQuotaExceededException", f"expected ServiceQuotaExceededException, got {code}"
    assert message == "The resultant tag set must not have more than 50 user tags.", (
        f"the ServiceQuotaExceededException said {message!r}, expected AWS's exact "
        f"'The resultant tag set must not have more than 50 user tags.'"
    )

    # Effect absent: the tag set is unchanged -- still exactly the original quota, no overflow tag.
    after = ca.list_tags_for_resource(resourceArn=resource_arn)["tags"]
    assert len(after) == quota, f"expected the tag count to remain {quota} after the rejected call, got {len(after)}"
    after_keys = {t["key"] for t in after}
    assert extra_tag["key"] not in after_keys, f"the overflow tag {extra_tag['key']!r} appeared after a rejected TagResource: {after_keys!r}"

    # Positive control: freeing one slot lets the same new tag be added successfully.
    ca.untag_resource(resourceArn=resource_arn, tagKeys=[full_tags[0]["key"]])
    ca.tag_resource(resourceArn=resource_arn, tags=[extra_tag])
    final = ca.list_tags_for_resource(resourceArn=resource_arn)["tags"]
    final_keys = {t["key"] for t in final}
    assert len(final) == quota, f"expected the tag count to be back at {quota} after freeing a slot and re-adding, got {len(final)}"
    assert extra_tag["key"] in final_keys, f"the previously rejected tag {extra_tag['key']!r} did not succeed once a slot was free: {final_keys!r}"
    assert full_tags[0]["key"] not in final_keys, f"the untagged key {full_tags[0]['key']!r} reappeared: {final_keys!r}"



if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
