"""max-message-size-lowered-spares-already-enqueued-messages."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "max-message-size-lowered-spares-already-enqueued-messages"
GROUP = 'state'
SERVICES = ['sqs']

_TAGS = {"sim2real:managed": "true", "sim2real": "max-size-lowered"}

_NEW_LIMIT = 1024
_BIG = 4096
# Bound on how long the lowered limit may take to govern SendMessage.
_CONVERGE_S = 90.0


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Lowering MaximumMessageSize only bounds future sends.

    Oversize sends are then refused, but a larger message enqueued before is delivered byte-exact.
    """
    sqs = ctx.client("sqs")
    token = uuid.uuid4().hex[:8]
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-"), tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    head = f"before-change-{token}-"
    big_body = head + "x" * (_BIG - len(head))
    sqs.send_message(QueueUrl=url, MessageBody=big_body)

    sqs.set_queue_attributes(QueueUrl=url, Attributes={"MaximumMessageSize": str(_NEW_LIMIT)})
    stored = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["MaximumMessageSize"])[
        "Attributes"]["MaximumMessageSize"]
    assert stored == str(_NEW_LIMIT), f"MaximumMessageSize read back {stored!r}"

    # Wait until the new limit refuses a body the size of the stored one.
    accepted_late: list[str] = []
    refused = None
    deadline = time.monotonic() + _CONVERGE_S
    while refused is None and time.monotonic() < deadline:
        probe_head = f"after-change-{len(accepted_late)}-{token}-"
        probe = probe_head + "y" * (_BIG - len(probe_head))
        try:
            sqs.send_message(QueueUrl=url, MessageBody=probe)
            accepted_late.append(probe)
            time.sleep(2)
        except ClientError as exc:
            refused = (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
    assert refused is not None, (
        f"a {_BIG}-byte body was still accepted {_CONVERGE_S:.0f}s after lowering "
        f"MaximumMessageSize to {_NEW_LIMIT}")
    assert refused == ("InvalidParameterValue",
                       f"One or more parameters are invalid. Reason: Message must be shorter "
                       f"than {_NEW_LIMIT} bytes."), f"oversize send refused with {refused!r}"

    at_limit_head = f"at-limit-{token}-"
    at_limit = at_limit_head + "z" * (_NEW_LIMIT - len(at_limit_head))
    sqs.send_message(QueueUrl=url, MessageBody=at_limit)

    bodies: list[str] = []
    empties = 0
    deadline = time.monotonic() + 60
    while empties < 3 and time.monotonic() < deadline:
        batch = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10,
                                    WaitTimeSeconds=2).get("Messages", [])
        empties = 0 if batch else empties + 1
        for m in batch:
            bodies.append(m["Body"])
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
    assert big_body in bodies, (
        f"the {_BIG}-byte message enqueued before MaximumMessageSize was lowered to {_NEW_LIMIT} "
        f"was not delivered intact; received sizes {sorted(len(b) for b in bodies)!r}")
    assert at_limit in bodies, f"the {_NEW_LIMIT}-byte body sent after the change was not delivered"
    assert sorted(bodies) == sorted([big_body, at_limit, *accepted_late]), (
        f"queue must hold exactly the pre-change message, the sends accepted while the limit "
        f"propagated, and the at-limit body; received sizes {sorted(len(b) for b in bodies)!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
