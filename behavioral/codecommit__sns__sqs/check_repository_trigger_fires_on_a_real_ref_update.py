"""repository-trigger-fires-on-a-real-ref-update."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "repository-trigger-fires-on-a-real-ref-update"
GROUP = 'data-plane'
SERVICES = ['codecommit', 'sns', 'sqs']


@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "dp:api",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """A trigger scoped to updateReference on main publishes a notification naming that ref and
    the exact commit id created, while a commit on an unlisted branch publishes nothing (proven
    by a later main commit's notification arriving, not by a sleep).
    """
    cc = ctx.client("codecommit")
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")

    topic_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-behav-cctrig-t-"),
        Tags=[{"Key": "sim2real", "Value": "cctrig"}])["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    queue_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-cctrig-q-"),
                                 tags={"sim2real": "cctrig"})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    # Without this policy SNS drops every delivery silently, which would make the
    # absence assertions below pass for the wrong reason.
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Sid": "AllowThisTopic", "Effect": "Allow",
                       "Principal": {"Service": "sns.amazonaws.com"},
                       "Action": "sqs:SendMessage", "Resource": queue_arn,
                       "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}}}],
    })})
    subscription = sns.subscribe(TopicArn=topic_arn, Protocol="sqs",
                                 Endpoint=queue_arn)["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=subscription))

    repo = ctx.unique_name("sim2real-behav-cctrig-r-")
    meta = cc.create_repository(repositoryName=repo,
                              tags={"sim2real": "cctrig"})["repositoryMetadata"]
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo))
    seed = cc.put_file(repositoryName=repo, branchName="main", filePath="seed.txt",
                       fileContent=b"seed\n", commitMessage="seed")["commitId"]
    cc.create_branch(repositoryName=repo, branchName="unlisted", commitId=seed)

    trigger_name = ctx.unique_name("sim2real-behav-cctrig-n-")
    trigger = {"name": trigger_name, "destinationArn": topic_arn,
               "branches": ["main"], "events": ["updateReference"]}
    config_id = cc.put_repository_triggers(repositoryName=repo,
                                          triggers=[trigger])["configurationId"]
    ctx.on_cleanup(lambda: cc.put_repository_triggers(repositoryName=repo, triggers=[]))
    assert config_id, "PutRepositoryTriggers returned no configurationId"

    stored = cc.get_repository_triggers(repositoryName=repo)
    assert [t["name"] for t in stored["triggers"]] == [trigger_name], (
        f"GetRepositoryTriggers reports {[t['name'] for t in stored['triggers']]!r}, "
        f"expected exactly [{trigger_name!r}]"
    )
    assert stored["triggers"][0]["branches"] == ["main"], (
        f"the stored trigger's branches are {stored['triggers'][0]['branches']!r}, "
        f"expected ['main']"
    )

    # Barrier 1: the service can reach this topic and the topic can reach this queue.
    # TestRepositoryTriggers publishes a synthetic TriggerEventTest record, so draining it
    # both proves the whole path and clears the queue before the real writes.
    tested = cc.test_repository_triggers(repositoryName=repo, triggers=[trigger])
    assert tested["successfulExecutions"] == [trigger_name], (
        f"TestRepositoryTriggers reports successfulExecutions "
        f"{tested['successfulExecutions']!r} and failedExecutions "
        f"{tested['failedExecutions']!r}; the notification path is not usable"
    )
    synthetic = _drain(sqs, queue_url, want=1, event_name="TriggerEventTest",
                       timeout_s=90.0)
    assert len(synthetic) == 1, (
        f"the TestRepositoryTriggers notification never arrived in the queue "
        f"({len(synthetic)} collected); the SNS -> SQS leg is not working, so nothing "
        f"below could distinguish 'not published' from 'not delivered'"
    )

    # Now three real ref updates: main, the unlisted branch, main again.
    first_main = cc.put_file(repositoryName=repo, branchName="main", filePath="one.txt",
                             fileContent=b"one\n", parentCommitId=seed,
                             commitMessage="first on main")["commitId"]
    unlisted_commit = cc.put_file(repositoryName=repo, branchName="unlisted",
                                  filePath="unlisted.txt", fileContent=b"unlisted\n",
                                  parentCommitId=seed,
                                  commitMessage="on the unlisted branch")["commitId"]
    second_main = cc.put_file(repositoryName=repo, branchName="main", filePath="two.txt",
                              fileContent=b"two\n", parentCommitId=first_main,
                              commitMessage="second on main")["commitId"]
    assert len({first_main, unlisted_commit, second_main}) == 3, (
        "the three writes did not produce three distinct commit ids"
    )

    # Barrier 2: wait for the *second* main notification. It was published after the
    # unlisted branch's write, so once it has arrived the unlisted write's own
    # notification has had strictly longer than the observed delivery latency to appear.
    delivered = _drain(sqs, queue_url, want=2, event_name="ReferenceChanges",
                       timeout_s=120.0, until=lambda records: any(
                           r["codecommit"]["references"][0]["commit"] == second_main
                           for r in records))
    commits = [r["codecommit"]["references"][0]["commit"] for r in delivered]
    assert second_main in commits, (
        f"the second commit on main ({second_main!r}) never produced a notification; "
        f"collected {commits!r} -- without it the absence check below proves nothing"
    )
    assert first_main in commits, (
        f"the first commit on main ({first_main!r}) produced no notification; collected "
        f"{commits!r}"
    )

    # The listed branch's record names the ref and the exact commit created.
    matching = [r for r in delivered
                if r["codecommit"]["references"][0]["commit"] == first_main]
    assert len(matching) == 1, (
        f"{len(matching)} notifications name the first commit {first_main!r}; expected one"
    )
    record = matching[0]
    assert record["codecommit"]["references"][0]["ref"] == "refs/heads/main", (
        f"the record's ref is {record['codecommit']['references'][0]['ref']!r}, expected "
        f"'refs/heads/main' -- the fully qualified ref, not the short branch name"
    )
    assert record["eventSourceARN"] == meta["Arn"], (
        f"the record's eventSourceARN is {record['eventSourceARN']!r}, expected this "
        f"repository's ARN {meta['Arn']!r}"
    )
    assert record["eventSource"] == "aws:codecommit", (
        f"the record's eventSource is {record['eventSource']!r}, expected 'aws:codecommit'"
    )
    assert record["eventName"] == "ReferenceChanges", (
        f"the record's eventName is {record['eventName']!r}, expected 'ReferenceChanges' "
        f"for a real ref update"
    )
    assert record["eventTriggerName"] == trigger_name, (
        f"the record's eventTriggerName is {record['eventTriggerName']!r}, expected "
        f"{trigger_name!r}"
    )
    assert record["eventTriggerConfigId"] == config_id, (
        f"the record's eventTriggerConfigId is {record['eventTriggerConfigId']!r}, expected "
        f"the configurationId PutRepositoryTriggers returned, {config_id!r}"
    )

    # Effect absent: the unlisted branch's commit appears in nothing that arrived, and its
    # ref is named nowhere.
    assert unlisted_commit not in commits, (
        f"the commit on the unlisted branch ({unlisted_commit!r}) produced a notification; "
        f"the trigger lists only 'main'. Every collected commit id: {commits!r}"
    )
    refs = [r["codecommit"]["references"][0]["ref"] for r in delivered]
    assert set(refs) == {"refs/heads/main"}, (
        f"notifications arrived for refs {refs!r}; the trigger is scoped to main alone"
    )


def _drain(sqs, queue_url, *, want: int, event_name: str, timeout_s: float, until=None):
    """Long-poll the queue, returning the CodeCommit records whose eventName matches.

    Records with a different eventName are consumed and discarded -- TestRepositoryTriggers
    emits a synthetic TriggerEventTest record carrying a commit id that exists in no
    repository, and counting it as a real delivery would corrupt every assertion here.
    """
    records, deadline = [], time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        received = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10,
                                       WaitTimeSeconds=10)
        for message in received.get("Messages", []):
            payload = json.loads(json.loads(message["Body"])["Message"])
            for record in payload["Records"]:
                if record["eventName"] == event_name:
                    records.append(record)
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=message["ReceiptHandle"])
        if len(records) >= want and (until is None or until(records)):
            return records
    return records


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
