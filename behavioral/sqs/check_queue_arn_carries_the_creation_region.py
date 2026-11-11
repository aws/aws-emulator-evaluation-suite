"""queue-arn-carries-the-creation-region."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "queue-arn-carries-the-creation-region"
GROUP = "naming"
SERVICES = ["sqs"]

ALT_REGION = "us-east-1"
SETTLE_S = 60.0
NO_SUCH_QUEUE = "AWS.SimpleQueueService.NonExistentQueue"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A queue's ARN and URL name the region it was created in, and two same-named queues in two
    regions are separate resources that do not appear in each other's listing.
    """
    home_region = ctx.region
    assert home_region != ALT_REGION, (
        f"this check needs two distinct regions; the harness region is {home_region!r} which equals "
        f"the alternate {ALT_REGION!r}. Change ALT_REGION"
    )
    home = ctx.client("sqs")
    alt = ctx.client("sqs", region=ALT_REGION)

    # Two explicit regions and one reused name: a hardcoded region or a store not partitioned by
    # region is invisible to a single-region run.
    shared_name = ctx.unique_name("sim2real-behav-region-q-")

    home_url = home.create_queue(QueueName=shared_name, tags={"sim2real:managed": "true"})["QueueUrl"]
    ctx.on_cleanup(lambda: _delete_if_present(home, home_url))
    alt_url = alt.create_queue(QueueName=shared_name, tags={"sim2real:managed": "true"})["QueueUrl"]
    ctx.on_cleanup(lambda: _delete_if_present(alt, alt_url))

    # Each ARN names its own region.
    for label, client, url, expected_region in (
        ("home", home, home_url, home_region),
        ("alt", alt, alt_url, ALT_REGION),
    ):
        arn = client.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
            "QueueArn"
        ]
        parts = arn.split(":")
        assert len(parts) == 6 and parts[0] == "arn" and parts[2] == "sqs", (
            f"[{label}] malformed QueueArn {arn!r}"
        )
        assert parts[3] == expected_region, (
            f"[{label}] QueueArn must name the region the queue was created in: expected "
            f"{expected_region!r}, got {parts[3]!r} (full ARN {arn!r}). A target that hardcodes one "
            f"region reports the same value for both queues and fails on whichever is not that region"
        )
        assert parts[5] == shared_name, (
            f"[{label}] QueueArn must end in the queue name {shared_name!r}, got {arn!r}"
        )

    # The URL is regional too.
    # An AWS host must name the region; a host an emulator published as its own carries none, so
    # those URLs are graded through ctx.published_url_mismatch (scheme only).
    assert home_url != alt_url or (
        ctx.published_url_mismatch(home_url, labels=(home_region,)) is None
        and ctx.published_url_mismatch(alt_url, labels=(ALT_REGION,)) is None
    ), f"two queues in two regions must have distinct URLs; both were {home_url!r}"
    assert (home_region in home_url and ALT_REGION in alt_url) or (
        ctx.published_url_mismatch(home_url, labels=(home_region,)) is None
        and ctx.published_url_mismatch(alt_url, labels=(ALT_REGION,)) is None
    ), (
        f"each QueueUrl must carry its own region: {home_url!r} / {alt_url!r}"
    )

    # Region is a state boundary: neither queue appears in the other's listing.
    # The two queues share a name, so a target that does not partition by region can only show one of
    # them.
    home_names = _queue_names(home, shared_name)
    alt_names = _queue_names(alt, shared_name)
    assert home_names == {shared_name}, (
        f"ListQueues in {home_region!r} must show exactly the queue created there, got {home_names!r}"
    )
    assert alt_names == {shared_name}, (
        f"ListQueues in {ALT_REGION!r} must show exactly the queue created there, got {alt_names!r}"
    )

    # Deleting one leaves the other.
    alt.delete_queue(QueueUrl=alt_url)
    _await_absent(alt, shared_name)
    still_there = home.get_queue_attributes(QueueUrl=home_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    assert still_there.split(":")[3] == home_region, (
        f"deleting the {ALT_REGION!r} queue must not disturb the {home_region!r} one; its ARN now "
        f"reads {still_there!r}"
    )


def _queue_names(sqs, prefix_name: str) -> set[str]:
    """Queue names in this region with the given unique-name prefix, paginated."""
    found: set[str] = set()
    for page in sqs.get_paginator("list_queues").paginate(QueueNamePrefix=prefix_name):
        for url in page.get("QueueUrls", []) or []:
            found.add(url.rsplit("/", 1)[-1])
    return found


def _await_absent(sqs, name: str) -> None:
    """Wait for the queue to leave ListQueues; SQS deletion can take up to 60s to show."""
    deadline = time.monotonic() + SETTLE_S
    last: set[str] = set()
    while time.monotonic() < deadline:
        last = _queue_names(sqs, name)
        if not last:
            return
        time.sleep(3.0)
    raise AssertionError(f"queue {name!r} still listed {SETTLE_S}s after delete (last={last!r})")


def _delete_if_present(sqs, url: str) -> None:
    try:
        sqs.delete_queue(QueueUrl=url)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != NO_SUCH_QUEUE:
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
