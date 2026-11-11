"""deploy-codecommit-repository-trigger-enforced."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "deploy-codecommit-repository-trigger-enforced"
GROUP = "deploy"
SERVICES = ["codecommit"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """CloudFormation-declared repository triggers are returned by GetRepositoryTriggers, pass
    TestRepositoryTriggers, and deliver an SNS notification to a subscribed SQS queue when a
    real commit is pushed."""
    repo_name = ctx.unique_name("sim2real-behav-trigrepo-")
    trigger_name = ctx.unique_name("sim2real-behav-trigger-")

    queue_url, queue_arn = _create_queue(ctx)
    topic_arn = _create_topic(ctx)
    _subscribe_queue_to_topic(ctx, topic_arn, queue_url, queue_arn)

    template = {
        "Resources": {
            "Repo": {
                "Type": "AWS::CodeCommit::Repository",
                "Properties": {
                    "RepositoryName": repo_name,
                    "Triggers": [
                        {
                            "Name": trigger_name,
                            "DestinationArn": topic_arn,
                            "Events": ["all"],
                            "Branches": [],
                        }
                    ],
                },
            }
        }
    }
    _deploy_cfn(ctx, template)

    codecommit = ctx.client("codecommit")

    # GetRepositoryTriggers reflects the CFN-declared trigger configuration
    trig_resp = codecommit.get_repository_triggers(repositoryName=repo_name)
    triggers = trig_resp["triggers"]
    assert len(triggers) == 1, f"expected exactly 1 trigger from the CFN template, got {triggers!r}"
    assert triggers[0]["name"] == trigger_name, (
        f"trigger name is {triggers[0]['name']!r}, expected {trigger_name!r}"
    )
    assert triggers[0]["destinationArn"] == topic_arn, (
        f"destinationArn is {triggers[0]['destinationArn']!r}, expected {topic_arn!r}"
    )
    assert triggers[0]["events"] == ["all"], (
        f"events is {triggers[0]['events']!r}, expected ['all']"
    )

    # TestRepositoryTriggers exercises the destination without a real repository event
    test_resp = codecommit.test_repository_triggers(
        repositoryName=repo_name,
        triggers=[
            {
                "name": trigger_name,
                "destinationArn": topic_arn,
                "events": ["all"],
                "branches": [],
            }
        ],
    )
    assert test_resp["successfulExecutions"] == [trigger_name], (
        f"successfulExecutions is {test_resp['successfulExecutions']!r}, expected "
        f"[{trigger_name!r}]; failedExecutions was {test_resp['failedExecutions']!r}"
    )
    assert test_resp["failedExecutions"] == [], (
        f"failedExecutions is {test_resp['failedExecutions']!r}, expected []"
    )

    # Now cause a real repository event: the first commit on a brand-new repository
    # creates the "main" branch (a createReference-class event), which the "all"
    # trigger matches and must actually deliver to the subscribed SQS queue.
    put_result = codecommit.put_file(
        repositoryName=repo_name,
        branchName="main",
        fileContent=b"trigger-fire-check\n",
        filePath="TRIGGER.md",
    )
    real_commit_id = put_result["commitId"]

    def _is_real_commit_notification(payload: dict) -> bool:
        try:
            refs = payload["Records"][0]["codecommit"]["references"]
        except (KeyError, IndexError, TypeError):
            return False
        return any(ref.get("commit") == real_commit_id for ref in refs)

    payload = _poll_for_matching_message(
        ctx, queue_url, _is_real_commit_notification, timeout_s=90.0
    )
    assert payload is not None, "trigger never delivered a notification for the real commit"
    record = payload["Records"][0]
    assert record["eventTriggerName"] == trigger_name, (
        f"eventTriggerName is {record['eventTriggerName']!r}, expected {trigger_name!r}"
    )
    assert repo_name in record["eventSourceARN"], (
        f"eventSourceARN is {record['eventSourceARN']!r}, expected it to contain {repo_name!r}"
    )
    matching_refs = [
        ref for ref in record["codecommit"]["references"] if ref.get("commit") == real_commit_id
    ]
    assert matching_refs and matching_refs[0]["ref"] == "refs/heads/main", (
        f"references matching commit {real_commit_id!r} are {matching_refs!r}, expected exactly "
        f"one with ref 'refs/heads/main'"
    )




def _deploy_cfn(ctx, template: dict) -> str:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-behav-trigstack-")

    def _cleanup() -> None:
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
        )

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Tags=[{"Key": "sim2real", "Value": "ccdtrig"}],
    )
    ctx.on_cleanup(_cleanup)
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )
    return stack_name


def _create_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-trigq-"),
        tags={"sim2real": "ccdtrig"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    return url, arn


def _create_topic(ctx) -> str:
    sns = ctx.client("sns")
    arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-behav-trigtopic-"),
        Tags=[{"Key": "sim2real", "Value": "ccdtrig"}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    return arn


def _subscribe_queue_to_topic(ctx, topic_arn: str, queue_url: str, queue_arn: str) -> None:
    sqs = ctx.client("sqs")
    sns = ctx.client("sns")
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "sns.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue_arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})
    sub = sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)
    sub_arn = sub["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub_arn))


def _poll_for_matching_message(
    ctx,
    queue_url: str,
    predicate: Callable[[dict], bool],
    timeout_s: float = 90.0,
    interval_s: float = 3.0,
) -> dict[str, Any] | None:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            try:
                envelope = json.loads(msg["Body"])
                payload = json.loads(envelope["Message"])
            except (KeyError, ValueError, TypeError):
                continue
            if predicate(payload):
                return payload
        time.sleep(interval_s)
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
