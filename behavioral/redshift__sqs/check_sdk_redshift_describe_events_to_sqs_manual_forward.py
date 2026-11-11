"""sdk-redshift-describe-events-to-sqs-manual-forward."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "sdk-redshift-describe-events-to-sqs-manual-forward"
GROUP = "data-format"
SERVICES = ["redshift", "sqs"]


@tags("axis:happy-path", "cap:c2", "cap:c5", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Redshift DescribeEventCategories cluster event forwarded through SQS keeps its SourceType,
    EventId, EventCategories, EventDescription and Severity. DescribeEventCategories is used
    because it is a fixed catalog that needs no cluster, unlike DescribeEvents.
    """
    redshift = ctx.client("redshift")
    sqs = ctx.client("sqs")

    categories = redshift.describe_event_categories(SourceType="cluster")[
        "EventCategoriesMapList"
    ]
    assert categories, "DescribeEventCategories returned no cluster categories"
    category_map = categories[0]
    assert category_map["SourceType"] == "cluster", (
        f"expected SourceType 'cluster', got {category_map['SourceType']!r}"
    )
    events_list = category_map["Events"]
    assert events_list, "cluster event category map had no events"
    sample_event = events_list[0]

    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-rs-descevents-"),
        tags={"sim2real:managed": "true", "sim2real": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))

    payload = {
        "SourceType": category_map["SourceType"],
        "Event": sample_event,
    }
    sqs.send_message(QueueUrl=queue_url, MessageBody=json.dumps(payload))

    received = _wait_for_message(sqs, queue_url, timeout_s=30)
    assert received is not None, "manually forwarded DescribeEventCategories payload never arrived"
    forwarded = json.loads(received)
    assert forwarded["SourceType"] == "cluster", (
        f"expected forwarded SourceType 'cluster', got {forwarded['SourceType']!r}"
    )
    assert forwarded["Event"]["EventId"] == sample_event["EventId"], (
        f"EventId did not survive the round trip: sent {sample_event['EventId']!r}, "
        f"got {forwarded['Event']['EventId']!r}"
    )
    assert forwarded["Event"]["EventCategories"] == sample_event["EventCategories"], (
        f"EventCategories did not survive the round trip: sent {sample_event['EventCategories']!r}, "
        f"got {forwarded['Event']['EventCategories']!r}"
    )
    assert forwarded["Event"]["EventDescription"] == sample_event["EventDescription"], (
        f"EventDescription did not survive the round trip: sent {sample_event['EventDescription']!r}, "
        f"got {forwarded['Event']['EventDescription']!r}"
    )
    assert forwarded["Event"]["Severity"] == sample_event["Severity"], (
        f"Severity did not survive the round trip: sent {sample_event['Severity']!r}, "
        f"got {forwarded['Event']['Severity']!r}"
    )


def _wait_for_message(sqs, queue_url, timeout_s=30.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5
        )
        for m in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
            return m["Body"]
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
