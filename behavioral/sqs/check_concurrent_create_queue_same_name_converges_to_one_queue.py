"""concurrent-create-queue-same-name-converges-to-one-queue."""
from __future__ import annotations

import concurrent.futures
import threading
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-create-queue-same-name-converges-to-one-queue"
GROUP = "concurrency"
SERVICES = ["sqs"]

_CREATORS = 10
_SETTLE_S = 60.0
_ATTRS = {"VisibilityTimeout": "41", "DelaySeconds": "0"}
_TAGS = {"sim2real": "concurrent-create-queue-same-name-converges-to-one-queue"}
_NO_SUCH_QUEUE = "AWS.SimpleQueueService.NonExistentQueue"


def _listed(sqs, name: str) -> list[str]:
    urls: list[str] = []
    for page in sqs.get_paginator("list_queues").paginate(QueueNamePrefix=name):
        urls.extend(u for u in page.get("QueueUrls", []) or [] if u.rsplit("/", 1)[-1] == name)
    return urls


def _delete_quietly(sqs, url: str) -> None:
    try:
        sqs.delete_queue(QueueUrl=url)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != _NO_SUCH_QUEUE:
            raise


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Ten simultaneous identical CreateQueue calls for one name all succeed with the same QueueUrl;
    the name lists once and the queue carries the requested attributes and tags.
    """
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-conc-create-")
    barrier = threading.Barrier(_CREATORS)

    def create(_: int):
        barrier.wait(timeout=30)
        try:
            return sqs.create_queue(QueueName=name, Attributes=_ATTRS, tags=_TAGS)["QueueUrl"]
        except ClientError as exc:
            return exc.response.get("Error", {})

    with concurrent.futures.ThreadPoolExecutor(max_workers=_CREATORS) as ex:
        results = list(ex.map(create, range(_CREATORS)))
    urls = [r for r in results if isinstance(r, str)]
    for u in set(urls):
        ctx.on_cleanup(lambda u=u: _delete_quietly(sqs, u))

    errors = [r for r in results if not isinstance(r, str)]
    assert errors == [], f"{len(errors)} of {_CREATORS} identical concurrent creates failed: {errors!r}"
    assert len(set(urls)) == 1, (
        f"{_CREATORS} identical concurrent creates returned {len(set(urls))} distinct URLs"
    )
    url = urls[0]
    assert url.rsplit("/", 1)[-1] == name, f"the URL does not end in the queue name {name!r}"

    listed: list[str] = []
    deadline = time.monotonic() + _SETTLE_S
    while time.monotonic() < deadline:
        listed = _listed(sqs, name)
        if listed:
            break
        time.sleep(3)
    assert listed == [url], f"ListQueues showed {len(listed)} queue(s) named {name!r}, expected 1"

    got = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=sorted(_ATTRS))["Attributes"]
    assert got == _ATTRS, f"the raced queue carries {got!r}, expected {_ATTRS!r}"
    tags_read = sqs.list_queue_tags(QueueUrl=url).get("Tags", {})
    assert tags_read == _TAGS, f"the raced queue carries tags {tags_read!r}, expected {_TAGS!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
