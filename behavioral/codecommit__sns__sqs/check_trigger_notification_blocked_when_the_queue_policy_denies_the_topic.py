"""trigger-notification-blocked-when-the-queue-policy-denies-the-topic."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "trigger-notification-blocked-when-the-queue-policy-denies-the-topic"
GROUP = 'error-semantics'
SERVICES = ['codecommit', 'sns', 'sqs']


@tags(
    "axis:negative-delivery",
    "concern:e2e",
    "concern:eventing",
    "cap:c1",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """A queue whose policy scopes sqs:SendMessage to a different topic receives none of a
    trigger's notifications while its correctly scoped twin receives all of them, and it starts
    receiving once the policy is repaired, so the queue policy alone suppressed delivery.
    """
    cc = ctx.client("codecommit")
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")

    # The topic the trigger publishes to, and a second real topic used only as a
    # well-formed ARN for the blocked queue's condition -- so the broken policy differs
    # from the working one in exactly one value, not in its shape.
    topic_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-behav-ccdeny-t-"),
        Tags=[{"Key": "sim2real", "Value": "ccdeny"}])["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))
    other_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-behav-ccdeny-other-"),
        Tags=[{"Key": "sim2real", "Value": "ccdeny"}])["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=other_arn))
    assert topic_arn != other_arn, "the two topics collided"

    def _queue(prefix, allowed_topic):
        url = sqs.create_queue(QueueName=ctx.unique_name(prefix),
                               tags={"sim2real": "ccdeny"})["QueueUrl"]
        ctx.on_cleanup(lambda u=url: sqs.delete_queue(QueueUrl=u))
        arn = sqs.get_queue_attributes(QueueUrl=url,
                                       AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
        sqs.set_queue_attributes(QueueUrl=url, Attributes={
            "Policy": _policy(arn, allowed_topic)})
        return url, arn

    good_url, good_arn = _queue("sim2real-behav-ccdeny-good-", topic_arn)
    # Break exactly one thing: the same policy, same principal, same action, same
    # resource -- a different SourceArn.
    blocked_url, blocked_arn = _queue("sim2real-behav-ccdeny-blocked-", other_arn)

    good_sub = sns.subscribe(TopicArn=topic_arn, Protocol="sqs",
                             Endpoint=good_arn)["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=good_sub))
    blocked_sub = sns.subscribe(TopicArn=topic_arn, Protocol="sqs",
                                Endpoint=blocked_arn)["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=blocked_sub))
    subscribed = _subscription_endpoints(sns, topic_arn)
    assert sorted(subscribed) == sorted([good_arn, blocked_arn]), (
        f"the topic's subscriptions are {sorted(subscribed)!r}, expected both queues "
        f"{sorted([good_arn, blocked_arn])!r} -- the two paths must be identical apart "
        f"from the queue policy"
    )

    repo = ctx.unique_name("sim2real-behav-ccdeny-r-")
    cc.create_repository(repositoryName=repo, tags={"sim2real": "ccdeny"})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo))
    head = cc.put_file(repositoryName=repo, branchName="main", filePath="seed.txt",
                       fileContent=b"seed\n", commitMessage="seed")["commitId"]

    trigger_name = ctx.unique_name("sim2real-behav-ccdeny-n-")
    trigger = {"name": trigger_name, "destinationArn": topic_arn,
               "branches": ["main"], "events": ["updateReference"]}
    cc.put_repository_triggers(repositoryName=repo, triggers=[trigger])
    ctx.on_cleanup(lambda: cc.put_repository_triggers(repositoryName=repo, triggers=[]))

    # CodeCommit's own view is that the destination is fine: the defect is one hop further
    # on, which is exactly why it is invisible to the caller.
    tested = cc.test_repository_triggers(repositoryName=repo, triggers=[trigger])
    assert tested["successfulExecutions"] == [trigger_name], (
        f"TestRepositoryTriggers reports {tested!r}; the trigger must be accepted so the "
        f"only thing under test is the queue policy"
    )

    # Three real ref updates. Each one publishes once and fans to both subscriptions.
    commits = []
    for i in range(3):
        head = cc.put_file(repositoryName=repo, branchName="main",
                           filePath=f"file-{i}.txt",
                           fileContent=f"write {i}\n".encode("ascii"),
                           parentCommitId=head,
                           commitMessage=f"write {i}")["commitId"]
        commits.append(head)
    assert len(set(commits)) == 3, f"the three writes produced {set(commits)!r}"

    # The barrier: the correctly scoped queue must receive all three. Nothing about the
    # blocked queue is asserted until this holds.
    good = _drain(sqs, good_url, want=3, timeout_s=120.0)
    good_commits = [r["codecommit"]["references"][0]["commit"] for r in good]
    assert set(commits).issubset(set(good_commits)), (
        f"the correctly scoped queue received {good_commits!r}; all three commits "
        f"{commits!r} must arrive, otherwise the absence below is unmeasurable"
    )

    # Effect absent: the blocked queue got nothing, over a window in which its twin got
    # three separate deliveries.
    blocked = _drain(sqs, blocked_url, want=1, timeout_s=25.0)
    assert blocked == [], (
        f"the queue whose policy scopes sqs:SendMessage to {other_arn!r} received "
        f"{[r['codecommit']['references'][0]['commit'] for r in blocked]!r} from topic "
        f"{topic_arn!r}; a policy that does not allow this topic must suppress delivery "
        f"entirely, and its twin queue received {good_commits!r} over the same window"
    )
    # And the drop is a delivery-side drop, not a missing subscription: SNS still lists it.
    assert blocked_arn in _subscription_endpoints(sns, topic_arn), (
        f"{blocked_arn!r} is no longer subscribed to {topic_arn!r}; the absence must come "
        f"from the queue policy, not from a vanished subscription"
    )

    # Positive control, same queue, same topic, same trigger: repair the one broken value
    # and it receives. Without this step a typo in the queue url would also 'pass'.
    sqs.set_queue_attributes(QueueUrl=blocked_url,
                             Attributes={"Policy": _policy(blocked_arn, topic_arn)})
    repaired = []
    deadline = time.monotonic() + 80.0
    while not repaired and time.monotonic() < deadline:
        # A queue-policy change is eventually consistent and SNS does not retry a drop, so
        # the observable is a *fresh* notification after the repair, polled for rather than
        # slept on.
        head = cc.put_file(repositoryName=repo, branchName="main",
                           filePath="after-repair.txt",
                           fileContent=str(time.monotonic()).encode("ascii"),
                           parentCommitId=head,
                           commitMessage="after the policy repair")["commitId"]
        repaired = _drain(sqs, blocked_url, want=1, timeout_s=30.0)
    assert repaired, (
        f"the previously blocked queue {blocked_arn!r} still received nothing after its "
        f"policy was repaired to allow {topic_arn!r}; the queue was never reachable, so "
        f"the absence above proved nothing"
    )
    assert repaired[0]["codecommit"]["references"][0]["ref"] == "refs/heads/main", (
        f"the post-repair record's ref is "
        f"{repaired[0]['codecommit']['references'][0]['ref']!r}, expected 'refs/heads/main'"
    )
    assert repaired[0]["eventSource"] == "aws:codecommit", (
        f"the post-repair record's eventSource is {repaired[0]['eventSource']!r}"
    )


def _policy(queue_arn: str, topic_arn: str) -> str:
    """An SQS policy allowing exactly one SNS topic to send to this queue."""
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Sid": "AllowOneTopic", "Effect": "Allow",
                       "Principal": {"Service": "sns.amazonaws.com"},
                       "Action": "sqs:SendMessage", "Resource": queue_arn,
                       "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}}}],
    })


def _subscription_endpoints(sns, topic_arn: str):
    """Every endpoint subscribed to a topic, across all pages."""
    endpoints, token = [], None
    while True:
        kwargs = {"TopicArn": topic_arn}
        if token:
            kwargs["NextToken"] = token
        page = sns.list_subscriptions_by_topic(**kwargs)
        endpoints += [s["Endpoint"] for s in page.get("Subscriptions", [])]
        token = page.get("NextToken")
        if not token:
            return endpoints


def _drain(sqs, queue_url, *, want: int, timeout_s: float):
    """Long-poll a queue for CodeCommit ReferenceChanges records.

    TestRepositoryTriggers emits a synthetic TriggerEventTest record naming a commit that
    exists in no repository; it is consumed and discarded so it can never be counted as a
    real delivery.
    """
    records, deadline = [], time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        received = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10,
                                       WaitTimeSeconds=10)
        for message in received.get("Messages", []):
            payload = json.loads(json.loads(message["Body"])["Message"])
            for record in payload["Records"]:
                if record["eventName"] == "ReferenceChanges":
                    records.append(record)
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=message["ReceiptHandle"])
        if len(records) >= want:
            return records
    return records


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
