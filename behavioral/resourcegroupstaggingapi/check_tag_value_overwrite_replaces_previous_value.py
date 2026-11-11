"""tag-value-overwrite-replaces-previous-value."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "tag-value-overwrite-replaces-previous-value"
GROUP = "data-plane"
SERVICES = ["resourcegroupstaggingapi"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Re-tagging a resource with an existing key replaces the value in the index: the old value
    stops matching, the new one matches, and GetTagValues reports only the new value.
    """
    sqs = ctx.client("sqs")
    rgt = ctx.client("resourcegroupstaggingapi")

    key = ctx.unique_name("sim2real-behav-over-")

    q_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-q-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=q_url))
    q_arn = sqs.get_queue_attributes(QueueUrl=q_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    rgt.tag_resources(ResourceARNList=[q_arn], Tags={key: "first"})
    ctx.on_cleanup(lambda: rgt.untag_resources(ResourceARNList=[q_arn], TagKeys=[key]))

    first = _poll_until(
        lambda: {m["ResourceARN"] for m in _all_resources(
            rgt, TagFilters=[{"Key": key, "Values": ["first"]}])},
        lambda arns: arns == {q_arn},
        timeout_s=180.0,
    )
    assert first == {q_arn}, (
        f"before the overwrite, {key}=first matched {sorted(first)!r}, expected exactly {q_arn!r}"
    )

    replaced = rgt.tag_resources(ResourceARNList=[q_arn], Tags={key: "second"})
    assert replaced["FailedResourcesMap"] == {}, (
        f"re-tagging an existing key reported per-resource failures: {replaced['FailedResourcesMap']!r}"
    )

    second = _poll_until(
        lambda: {m["ResourceARN"] for m in _all_resources(
            rgt, TagFilters=[{"Key": key, "Values": ["second"]}])},
        lambda arns: arns == {q_arn},
        timeout_s=180.0,
    )
    assert second == {q_arn}, (
        f"after the overwrite, {key}=second matched {sorted(second)!r}, expected exactly {q_arn!r}"
    )

    # The replaced value must stop matching — this is the half an appending store would fail.
    stale = _poll_until(
        lambda: {m["ResourceARN"] for m in _all_resources(
            rgt, TagFilters=[{"Key": key, "Values": ["first"]}])},
        lambda arns: arns == set(),
        timeout_s=180.0,
    )
    assert stale == set(), (
        f"{key}=first still matched {sorted(stale)!r} after the key was overwritten to 'second'"
    )

    values = _all_tag_values(rgt, key)
    assert values == ["second"], (
        f"GetTagValues for {key!r} reported {values!r}, expected exactly ['second'] — one key on "
        f"one resource holds one value"
    )

    mapping = _all_resources(rgt, TagFilters=[{"Key": key}])
    assert len(mapping) == 1, (
        f"the key matched {len(mapping)} resources: {[m['ResourceARN'] for m in mapping]!r}"
    )
    pairs = {t["Key"]: t["Value"] for t in mapping[0]["Tags"]}
    assert pairs.get(key) == "second", (
        f"the resource's returned tags are {pairs!r}, which does not carry {key}=second"
    )


def _all_resources(rgt, **kwargs):
    """Every ResourceTagMapping for a GetResources query, following PaginationToken to the end."""
    out, token = [], ""
    while True:
        page = rgt.get_resources(**kwargs, **({"PaginationToken": token} if token else {}))
        out.extend(page["ResourceTagMappingList"])
        token = page["PaginationToken"]
        if not token:
            return out


def _all_tag_values(rgt, key):
    """Every value GetTagValues reports for one key, following PaginationToken to the end."""
    out, token = [], ""
    while True:
        page = rgt.get_tag_values(Key=key, **({"PaginationToken": token} if token else {}))
        out.extend(page["TagValues"])
        token = page["PaginationToken"]
        if not token:
            return out


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while time.monotonic() < deadline:
        if predicate(last):
            return last
        time.sleep(interval_s)
        last = probe()
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
