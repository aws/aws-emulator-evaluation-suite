"""tag-nonexistent-queue."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-nonexistent-queue"
GROUP = 'error-semantics'
SERVICES = ['sqs']

# Empirically-confirmed SQS error codes (real AWS returns these legacy
# "AWS.SimpleQueueService.*" prefixed codes, not the bare Smithy shape names).
NONEXISTENT_QUEUE = "AWS.SimpleQueueService.NonExistentQueue"


def _error_code(fn):
    """Call fn(); return botocore (Error.Code, Error.Message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _delete_queue(sqs, url):
    """Teardown DeleteQueue; an already-deleted queue answers NonExistentQueue."""
    try:
        sqs.delete_queue(QueueUrl=url)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != NONEXISTENT_QUEUE:
            raise


def _fake_queue_url(ctx, prefix_hint="nonexistent-"):
    """Return a well-formed queue URL that has never been created.

    Derives the URL prefix (scheme/host/account segment) from a real, transient
    probe queue so the fabricated URL matches whatever URL scheme the target
    implementation uses, while pointing at a queue name that has never existed
    (avoiding eventual-consistency windows around real deletions).
    """
    sqs = ctx.client("sqs")
    probe_name = ctx.unique_name("sim2real-behav-probe-")
    probe_url = sqs.create_queue(QueueName=probe_name)["QueueUrl"]
    ctx.on_cleanup(lambda: _delete_queue(sqs, probe_url))
    try:
        sqs.delete_queue(QueueUrl=probe_url)
    except Exception:
        pass
    base = probe_url.rsplit("/", 1)[0]
    return f"{base}/{ctx.unique_name('sim2real-behav-' + prefix_hint)}"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagQueue on a never-created QueueUrl fails with QueueDoesNotExist, and a positive
    control on a real queue proves the target does not simply reject every TagQueue call."""
    sqs = ctx.client("sqs")

    # Positive control: TagQueue succeeds and persists on a real, existing queue.
    real_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-tagnx-"))["QueueUrl"]
    ctx.on_cleanup(lambda: _delete_queue(sqs, real_url))
    sqs.tag_queue(QueueUrl=real_url, Tags={"a": "b"})
    control_tags = sqs.list_queue_tags(QueueUrl=real_url).get("Tags", {})
    assert control_tags.get("a") == "b", f"positive control did not persist tag: {control_tags!r}"

    fake_url = _fake_queue_url(ctx)
    code = _error_code(lambda: sqs.tag_queue(QueueUrl=fake_url, Tags={"a": "b"}))
    assert code == (NONEXISTENT_QUEUE, "The specified queue does not exist."), f"expected {NONEXISTENT_QUEUE}, got {code}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
