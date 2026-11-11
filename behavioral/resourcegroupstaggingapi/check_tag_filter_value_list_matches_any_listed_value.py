"""tag-filter-value-list-matches-any-listed-value."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "tag-filter-value-list-matches-any-listed-value"
GROUP = "data-plane"
SERVICES = ["resourcegroupstaggingapi"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A TagFilter's Values list matches any listed value and an omitted list matches every value,
    while a value that is only a prefix of a real one matches nothing.
    """
    sqs = ctx.client("sqs")
    sns = ctx.client("sns")
    rgt = ctx.client("resourcegroupstaggingapi")

    key = ctx.unique_name("sim2real-behav-vals-")

    q_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-q-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=q_url))
    q_arn = sqs.get_queue_attributes(QueueUrl=q_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    t_arn = sns.create_topic(Name=ctx.unique_name("sim2real-behav-t-"))["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=t_arn))

    rgt.tag_resources(ResourceARNList=[q_arn], Tags={key: "alpha"})
    ctx.on_cleanup(lambda: rgt.untag_resources(ResourceARNList=[q_arn], TagKeys=[key]))
    rgt.tag_resources(ResourceARNList=[t_arn], Tags={key: "beta"})
    ctx.on_cleanup(lambda: rgt.untag_resources(ResourceARNList=[t_arn], TagKeys=[key]))

    def matching(*values):
        f = {"Key": key}
        if values:
            f["Values"] = list(values)
        return {m["ResourceARN"] for m in _all_resources(rgt, TagFilters=[f])}

    # Key-only filter: value-agnostic, so it is also the positive control for both writes.
    any_value = _poll_until(matching, lambda arns: arns == {q_arn, t_arn}, timeout_s=180.0)
    assert any_value == {q_arn, t_arn}, (
        f"a Values-less filter on {key!r} matched {sorted(any_value)!r}, expected both the "
        f"alpha-tagged queue {q_arn!r} and the beta-tagged topic {t_arn!r}"
    )

    just_alpha = matching("alpha")
    assert just_alpha == {q_arn}, (
        f"Values=['alpha'] matched {sorted(just_alpha)!r}, expected exactly {q_arn!r}"
    )

    either = matching("alpha", "beta")
    assert either == {q_arn, t_arn}, (
        f"Values=['alpha','beta'] matched {sorted(either)!r}, expected both resources — a Values "
        f"list is an OR, not an AND"
    )

    neither = matching("gamma")
    assert neither == set(), (
        f"Values=['gamma'] matched {sorted(neither)!r}; nothing carries {key}=gamma"
    )

    # A value that is a PREFIX of a real one must not match: the comparison is equality.
    prefix = matching("alph")
    assert prefix == set(), (
        f"Values=['alph'] matched {sorted(prefix)!r}; tag-value matching must be exact, not a prefix"
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
