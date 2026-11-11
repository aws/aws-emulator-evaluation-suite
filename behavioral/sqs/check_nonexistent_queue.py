"""nonexistent-queue."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "nonexistent-queue"
GROUP = 'errors'
SERVICES = ['sqs']

ERR_NONEXISTENT_QUEUE = "AWS.SimpleQueueService.NonExistentQueue"

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """receive_message on non-existent QueueUrl → NonExistentQueue, with a positive
    control on a real queue so the negative can't be confused with a target where
    receive_message always errors."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-"), tags={"sim2real-check": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    control = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1)
    assert "Messages" not in control, (
        f"expected no messages on fresh queue, got {control.get('Messages')!r}"
    )

    ghost = f"{url.rsplit('/', 1)[0]}/{uuid.uuid4().hex[:8]}-ghost"
    try:
        sqs.receive_message(QueueUrl=ghost, MaxNumberOfMessages=1)
        code = None
    except ClientError as exc:
        code = (exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message"))
    assert code == (ERR_NONEXISTENT_QUEUE, "The specified queue does not exist."), f"expected {ERR_NONEXISTENT_QUEUE}, got {code!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
