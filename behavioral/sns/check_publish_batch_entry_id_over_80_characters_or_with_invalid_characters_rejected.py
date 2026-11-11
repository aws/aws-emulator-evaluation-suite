"""publish-batch-entry-id-over-80-characters-or-with-invalid-characters-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "publish-batch-entry-id-over-80-characters-or-with-invalid-characters-rejected"
GROUP = "publish-batch-limits"
SERVICES = ["sns"]


def _error(fn) -> tuple[str, str]:
    """(Code, Message) of the error ``fn`` raises; an unexpected success raises, naming it."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A PublishBatch with an 81-char or period-bearing entry Id is refused whole with
    InvalidBatchEntryId, delivering no sibling; 80-char Ids with "-" and "_" are all delivered.
    """
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    topic = sns.create_topic(Name=ctx.unique_name("sim2real-behav-sns-batchid-"),
                             Tags=[{"Key": "sim2real", "Value": CHECK}])["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic))
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-sns-batchid-"),
                           tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    q_arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "sqs:SendMessage", "Resource": q_arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": topic}}}]})})
    sub = sns.subscribe(TopicArn=topic, Protocol="sqs", Endpoint=q_arn, ReturnSubscriptionArn=True,
                        Attributes={"RawMessageDelivery": "true"})["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub))

    run_id = ctx.unique_name("r")
    long_id = "a" * 81
    code, message = _error(lambda: sns.publish_batch(TopicArn=topic, PublishBatchRequestEntries=[
        {"Id": "valid-sibling", "Message": f"{run_id}-sibling-1"},
        {"Id": long_id, "Message": f"{run_id}-long"}]))
    assert (code, message) == ("InvalidBatchEntryId",
                               f"The Id of a batch entry in the batch request is too long: {long_id}"), (
        f"an 81-character entry Id gave {code!r}: {message!r}")
    code, message = _error(lambda: sns.publish_batch(TopicArn=topic, PublishBatchRequestEntries=[
        {"Id": "valid-sibling", "Message": f"{run_id}-sibling-2"},
        {"Id": "has.period", "Message": f"{run_id}-period"}]))
    assert (code, message) == ("InvalidBatchEntryId",
                               "The Id of a batch entry in the batch request contains an impermissible character: has.period"), (
        f"an entry Id with a period gave {code!r}: {message!r}")

    ids = ["-".join(["x" * 39, "y" * 40]), "_".join(["p" * 40, "q" * 39])]
    assert all(len(i) == 80 for i in ids), f"the boundary Ids are {[len(i) for i in ids]!r} characters long"
    bodies = {i: f"{run_id}-ok-{n}" for n, i in enumerate(ids)}
    resp = sns.publish_batch(TopicArn=topic, PublishBatchRequestEntries=[
        {"Id": i, "Message": b} for i, b in bodies.items()])
    assert resp.get("Failed") == [] and sorted(s["Id"] for s in resp["Successful"]) == sorted(ids), (
        f"a batch of 80-character Ids must succeed entry for entry; Failed {resp.get('Failed')!r}, "
        f"{len(resp.get('Successful', []))} Successful")

    got: list[str] = []
    deadline, tail = time.monotonic() + 90, None
    while time.monotonic() < deadline and (tail is None or time.monotonic() < tail):
        if tail is None and set(bodies.values()) <= set(got):
            # Keep receiving briefly so a late sibling of a refused batch shows up.
            tail = time.monotonic() + 6
        for m in sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2).get("Messages", []):
            got.append(m["Body"])
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
    assert sorted(got) == sorted(bodies.values()), (
        f"the queue must hold exactly the accepted batch's two messages; it received {sorted(got)!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
