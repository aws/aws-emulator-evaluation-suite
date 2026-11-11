"""search-resources-type-filter-restricts-results."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "search-resources-type-filter-restricts-results"
GROUP = "data-plane"
SERVICES = ["resource-groups"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A ResourceTypeFilters-scoped query excludes a same-tagged resource of a different type."""
    sqs = ctx.client("sqs")
    sns = ctx.client("sns")
    rg = ctx.client("resource-groups")

    shared_value = ctx.unique_name("sim2real-rg-typefilter-")

    qname = ctx.unique_name("sim2real-rg-tf-sqs-")
    q_url = sqs.create_queue(QueueName=qname, tags={"sim2real-rg-marker": shared_value})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=q_url))
    q_arn = sqs.get_queue_attributes(QueueUrl=q_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    tname = ctx.unique_name("sim2real-rg-tf-sns-")
    t_arn = sns.create_topic(
        Name=tname, Tags=[{"Key": "sim2real-rg-marker", "Value": shared_value}]
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=t_arn))

    def query_for(resource_type_filters):
        return {
            "Type": "TAG_FILTERS_1_0",
            "Query": json.dumps(
                {
                    "ResourceTypeFilters": resource_type_filters,
                    "TagFilters": [{"Key": "sim2real-rg-marker", "Values": [shared_value]}],
                }
            ),
        }

    def probe(resource_type_filters):
        return rg.search_resources(ResourceQuery=query_for(resource_type_filters))["ResourceIdentifiers"]

    # Positive control: the topic must be independently discoverable by its OWN type filter,
    # so its absence below is the SQS-scoped filter excluding it, not the topic being unindexed.
    sns_matches = _poll_until(
        lambda: probe(["AWS::SNS::Topic"]),
        lambda ids: any(r["ResourceArn"] == t_arn for r in ids),
        timeout_s=240.0,
        interval_s=15.0,
    )
    sns_arns = [r["ResourceArn"] for r in sns_matches]
    if t_arn not in sns_arns:
        raise AssertionError(f"topic {t_arn} never appeared in its own type-filtered SearchResources results")

    matches = _poll_until(
        lambda: probe(["AWS::SQS::Queue"]),
        lambda ids: any(r["ResourceArn"] == q_arn for r in ids),
        timeout_s=240.0,
        interval_s=15.0,
    )
    arns = [r["ResourceArn"] for r in matches]
    if q_arn not in arns:
        raise AssertionError(f"queue {q_arn} never appeared in type-filtered SearchResources results")
    # The type filter must exclude the SNS topic even though it shares the same tag, and we have
    # already proven above that the topic is otherwise discoverable via its own type filter.
    assert t_arn not in arns, f"topic {t_arn} leaked into an AWS::SQS::Queue-scoped SearchResources result: {arns}"


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=5.0):
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
