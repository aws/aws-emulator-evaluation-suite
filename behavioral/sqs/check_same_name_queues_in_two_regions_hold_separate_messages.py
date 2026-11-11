"""same-name-queues-in-two-regions-hold-separate-messages."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "same-name-queues-in-two-regions-hold-separate-messages"
GROUP = "cross-region"
SERVICES = ["sqs"]

_TAGS = {"sim2real": "same-name-queues-in-two-regions-hold-separate-messages"}
_NO_SUCH_QUEUE = "AWS.SimpleQueueService.NonExistentQueue"


def _other_region(region: str) -> str:
    return "us-east-1" if region != "us-east-1" else "us-west-2"


def _drain(sqs, url: str, want: int, timeout_s: float = 30.0) -> list[dict]:
    got: list[dict] = []
    deadline = time.monotonic() + timeout_s
    while len(got) < want and time.monotonic() < deadline:
        got.extend(sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=3,
            MessageAttributeNames=["All"]).get("Messages", []))
    # One more look, so a message that should not be there is seen too.
    got.extend(sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2,
                                   MessageAttributeNames=["All"]).get("Messages", []))
    return got


def _delete_quietly(sqs, url: str) -> None:
    try:
        sqs.delete_queue(QueueUrl=url)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != _NO_SUCH_QUEUE:
            raise


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Same-name queues in two regions of one account are separate stores: each region's
    GetQueueUrl answers its own URL, messages are received only where sent, and deleting the
    other region's queue leaves the home queue's messages intact."""
    home_region = ctx.region
    alt_region = _other_region(home_region)
    home = ctx.client("sqs")
    alt = ctx.client("sqs", region=alt_region)
    name = ctx.unique_name("sim2real-behav-xr-msgs-")

    home_url = home.create_queue(QueueName=name, tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: _delete_quietly(home, home_url))
    alt_url = alt.create_queue(QueueName=name, tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: _delete_quietly(alt, alt_url))
    # An endpoint-relative URL may carry no region, so two regions may share it; an AWS host
    # must name its region.
    assert home_url != alt_url or (
        ctx.published_url_mismatch(home_url, labels=(home_region,)) is None
        and ctx.published_url_mismatch(alt_url, labels=(alt_region,)) is None
    ), f"both regions returned the same URL for {name!r}"

    assert home.get_queue_url(QueueName=name)["QueueUrl"] == home_url, (
        f"GetQueueUrl in {home_region!r} did not answer that region's own queue URL"
    )
    assert alt.get_queue_url(QueueName=name)["QueueUrl"] == alt_url, (
        f"GetQueueUrl in {alt_region!r} did not answer that region's own queue URL"
    )

    sent_home = {}
    for k in range(2):
        body = f"home-{k}-{name}"
        r = home.send_message(QueueUrl=home_url, MessageBody=body, MessageAttributes={
            "origin": {"DataType": "String", "StringValue": home_region}})
        sent_home[r["MessageId"]] = body
    alt_body = f"alt-{name}"
    alt_id = alt.send_message(QueueUrl=alt_url, MessageBody=alt_body, MessageAttributes={
        "origin": {"DataType": "String", "StringValue": alt_region}})["MessageId"]

    alt_got = _drain(alt, alt_url, 1)
    assert [(m["MessageId"], m["Body"]) for m in alt_got] == [(alt_id, alt_body)], (
        f"the {alt_region!r} queue must deliver exactly its own message; it delivered "
        f"{[m['Body'] for m in alt_got]!r}"
    )
    assert alt_got[0]["MessageAttributes"]["origin"]["StringValue"] == alt_region, (
        f"the {alt_region!r} message carries origin "
        f"{alt_got[0]['MessageAttributes']['origin']!r}"
    )

    # Delete the other region's queue; the home queue is unaffected and still holds its two.
    alt.delete_queue(QueueUrl=alt_url)
    home_got = _drain(home, home_url, 2)
    got_home = {m["MessageId"]: m["Body"] for m in home_got}
    assert got_home == sent_home, (
        f"the {home_region!r} queue must deliver exactly its own two messages after the "
        f"{alt_region!r} queue was deleted; it delivered {sorted(got_home.values())!r}"
    )
    origins = {m["MessageAttributes"]["origin"]["StringValue"] for m in home_got}
    assert origins == {home_region}, f"home messages carry origins {sorted(origins)!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
