"""tag-keys-and-values-summaries-reflect-tag-changes."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "tag-keys-and-values-summaries-reflect-tag-changes"
GROUP = "data-plane"
SERVICES = ["resourcegroupstaggingapi"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetTagKeys and GetTagValues are derived views over the index GetResources reads: a new key
    appears in both, and untagging its last holder withdraws it from both (membership only, since
    GetTagKeys is account-wide).
    """
    sqs = ctx.client("sqs")
    rgt = ctx.client("resourcegroupstaggingapi")

    key_a = ctx.unique_name("sim2real-behav-sum-a-")
    key_b = ctx.unique_name("sim2real-behav-sum-b-")

    q_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-q-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=q_url))
    q_arn = sqs.get_queue_attributes(QueueUrl=q_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    rgt.tag_resources(ResourceARNList=[q_arn], Tags={key_a: "alpha", key_b: "beta"})
    ctx.on_cleanup(lambda: rgt.untag_resources(ResourceARNList=[q_arn], TagKeys=[key_a, key_b]))

    present = _poll_until(
        lambda: _all_tag_keys(rgt),
        lambda keys: {key_a, key_b} <= set(keys),
        timeout_s=180.0,
    )
    missing = {key_a, key_b} - set(present)
    assert not missing, (
        f"GetTagKeys never reported {sorted(missing)!r} after TagResources wrote them; it returned "
        f"{len(present)} keys"
    )

    values_a = _all_tag_values(rgt, key_a)
    assert values_a == ["alpha"], (
        f"GetTagValues for {key_a!r} reported {values_a!r}, expected exactly ['alpha']"
    )
    values_b = _all_tag_values(rgt, key_b)
    assert values_b == ["beta"], (
        f"GetTagValues for {key_b!r} reported {values_b!r}, expected exactly ['beta']"
    )

    # The key summary must agree with what GetResources says holds the key.
    holders = {m["ResourceARN"] for m in _all_resources(rgt, TagFilters=[{"Key": key_a}])}
    assert holders == {q_arn}, (
        f"{key_a!r} is in the key summary but GetResources says it is held by {sorted(holders)!r}, "
        f"expected exactly {q_arn!r}"
    )

    rgt.untag_resources(ResourceARNList=[q_arn], TagKeys=[key_b])

    gone = _poll_until(
        lambda: (_all_tag_values(rgt, key_b), _all_tag_keys(rgt)),
        lambda pair: pair[0] == [] and key_b not in pair[1],
        timeout_s=180.0,
    )
    assert gone[0] == [], (
        f"GetTagValues for {key_b!r} still reports {gone[0]!r} after its only holder was untagged"
    )
    assert key_b not in gone[1], (
        f"GetTagKeys still reports {key_b!r} after its only holder was untagged"
    )
    # The sibling key is untouched: the withdrawal is per key, not a summary-wide reset.
    assert key_a in gone[1], (
        f"GetTagKeys dropped {key_a!r} too; untagging {key_b!r} must not affect it"
    )
    assert _all_tag_values(rgt, key_a) == ["alpha"], (
        f"GetTagValues for {key_a!r} changed to {_all_tag_values(rgt, key_a)!r} after an unrelated untag"
    )


# ===== helpers (self-contained) =====
def _all_resources(rgt, **kwargs):
    """Every ResourceTagMapping for a GetResources query, following PaginationToken to the end."""
    out, token = [], ""
    while True:
        page = rgt.get_resources(**kwargs, **({"PaginationToken": token} if token else {}))
        out.extend(page["ResourceTagMappingList"])
        token = page["PaginationToken"]
        if not token:
            return out


def _all_tag_keys(rgt):
    """Every key GetTagKeys reports for the account, following PaginationToken to the end."""
    out, token = [], ""
    while True:
        page = rgt.get_tag_keys(**({"PaginationToken": token} if token else {}))
        out.extend(page["TagKeys"])
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
