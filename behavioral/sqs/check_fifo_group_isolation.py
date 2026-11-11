"""fifo-group-isolation."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "fifo-group-isolation"
GROUP = 'fifo'
SERVICES = ['sqs']

@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """An in-flight FIFO message hides the rest of its own group but not other groups: with A1, A2
    in group A and B1 in group B, single-message receives (no delete) return the heads A1 and B1."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-") + ".fifo",
        Attributes={"FifoQueue": "true", "ContentBasedDeduplication": "true"},
        tags={"sim2real:managed": "true", "sim2real": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    for group, bodies in (("grp-A", ["A1", "A2"]), ("grp-B", ["B1"])):
        for body in bodies:
            sqs.send_message(QueueUrl=url, MessageBody=body, MessageGroupId=group)
    # MaxNumberOfMessages=1 so a single call cannot drain A1+A2 together.
    heads: list[str] = []
    for _ in range(12):
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=1)
        for m in resp.get("Messages", []):
            if m["Body"] not in heads:
                heads.append(m["Body"])
        if len(heads) >= 2:
            break
    assert sorted(heads) == ["A1", "B1"], (
        f"expected group heads A1,B1 receivable while in-flight (A2 blocked), got {sorted(heads)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
