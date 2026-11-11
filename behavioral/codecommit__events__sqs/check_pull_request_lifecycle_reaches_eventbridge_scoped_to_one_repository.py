"""pull-request-lifecycle-reaches-eventbridge-scoped-to-one-repository."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "pull-request-lifecycle-reaches-eventbridge-scoped-to-one-repository"
GROUP = "data-plane"
SERVICES = ["codecommit", "events", "sqs"]

#: EventBridge delivery for CodeCommit is documented as "best effort", so the poll is generous
#: and bounded, and it raises rather than returning what it has.
_DELIVERY_TIMEOUT_S = 180.0


@tags(
    "axis:happy-path",
    "cap:c2",
    "concern:e2e",
    "concern:eventing",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A pull request's create, source-branch-update and close each reach an SQS rule target as a
    CodeCommit Pull Request State Change naming the API's ids; a second repository's pull request
    never arrives, because the rule pattern pins `resources` to the first repository's ARN.

    Reference: https://docs.aws.amazon.com/codecommit/latest/userguide/monitoring-events.html
    """
    cc = ctx.client("codecommit")
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    sts = ctx.client("sts")

    account = sts.get_caller_identity()["Account"]

    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-ccev-q-"), tags={"sim2real": "ccev"}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]

    # The repository under observation, and a second one the rule must ignore.
    watched = cc.create_repository(
        repositoryName=ctx.unique_name("sim2real-behav-ccev-watched-"),
        tags={"sim2real": "ccev"},
    )["repositoryMetadata"]
    ctx.on_cleanup(
        lambda: cc.delete_repository(repositoryName=watched["repositoryName"])
    )
    ignored = cc.create_repository(
        repositoryName=ctx.unique_name("sim2real-behav-ccev-ignored-"),
        tags={"sim2real": "ccev"},
    )["repositoryMetadata"]
    ctx.on_cleanup(
        lambda: cc.delete_repository(repositoryName=ignored["repositoryName"])
    )

    rule_name = ctx.unique_name("sim2real-behav-ccev-r-")
    # `resources` is the structural barrier: the ignored repository's events carry a different
    # ARN and so cannot match, by construction rather than by waiting.
    rule_arn = events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(
            {
                "source": ["aws.codecommit"],
                "detail-type": ["CodeCommit Pull Request State Change"],
                "resources": [watched["Arn"]],
            }
        ),
        State="ENABLED",
        Description="sim2real codecommit EventBridge fidelity check",
        Tags=[{"Key": "sim2real", "Value": "ccev"}],
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))

    # Without this policy EventBridge drops every delivery silently, which would make the
    # absence assertion below pass for entirely the wrong reason.
    sqs.set_queue_attributes(
        QueueUrl=queue_url,
        Attributes={
            "Policy": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "AllowThisRule",
                            "Effect": "Allow",
                            "Principal": {"Service": "events.amazonaws.com"},
                            "Action": "sqs:SendMessage",
                            "Resource": queue_arn,
                            "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
                        }
                    ],
                }
            )
        },
    )
    target_id = "sim2real-queue"
    put_targets = events.put_targets(
        Rule=rule_name, Targets=[{"Id": target_id, "Arn": queue_arn}]
    )
    assert put_targets["FailedEntryCount"] == 0, (
        f"PutTargets reports FailedEntryCount {put_targets['FailedEntryCount']} and entries "
        f"{put_targets.get('FailedEntries')!r}; the queue is not wired to the rule, so nothing "
        f"below could distinguish 'not emitted' from 'not delivered'"
    )
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=[target_id]))

    watched_name = watched["repositoryName"]
    base = cc.put_file(
        repositoryName=watched_name,
        branchName="main",
        filePath="README.md",
        fileContent=b"base\n",
        commitMessage="base",
    )["commitId"]
    cc.create_branch(repositoryName=watched_name, branchName="feature", commitId=base)
    first_source = cc.put_file(
        repositoryName=watched_name,
        branchName="feature",
        filePath="work.txt",
        fileContent=b"first\n",
        parentCommitId=base,
        commitMessage="first feature commit",
    )["commitId"]

    pr = cc.create_pull_request(
        title="observed by EventBridge",
        targets=[
            {
                "repositoryName": watched_name,
                "sourceReference": "feature",
                "destinationReference": "main",
            }
        ],
    )["pullRequest"]
    pr_id = pr["pullRequestId"]
    api_open_status = pr["pullRequestStatus"]

    second_source = cc.put_file(
        repositoryName=watched_name,
        branchName="feature",
        filePath="work.txt",
        fileContent=b"second\n",
        parentCommitId=first_source,
        commitMessage="second feature commit updates the PR source",
    )["commitId"]
    assert second_source != first_source, "the source branch did not advance"

    # Ordered before the watched repository's last mutation, so that delivery proves this window.
    ignored_name = ignored["repositoryName"]
    ignored_base = cc.put_file(
        repositoryName=ignored_name,
        branchName="main",
        filePath="README.md",
        fileContent=b"base\n",
        commitMessage="base",
    )["commitId"]
    cc.create_branch(
        repositoryName=ignored_name, branchName="feature", commitId=ignored_base
    )
    cc.put_file(
        repositoryName=ignored_name,
        branchName="feature",
        filePath="work.txt",
        fileContent=b"unmatched\n",
        parentCommitId=ignored_base,
        commitMessage="work in the ignored repository",
    )
    ignored_pr_id = cc.create_pull_request(
        title="must not be delivered",
        targets=[
            {
                "repositoryName": ignored_name,
                "sourceReference": "feature",
                "destinationReference": "main",
            }
        ],
    )["pullRequest"]["pullRequestId"]
    assert ignored_pr_id != pr_id, "the two pull requests share an id"

    # The watched repository's LAST mutation, published after the ignored one. Its delivery is
    # what proves the ignored pull request's own window was open.
    closed = cc.update_pull_request_status(pullRequestId=pr_id, pullRequestStatus="CLOSED")[
        "pullRequest"
    ]
    api_closed_status = closed["pullRequestStatus"]

    records = _drain_until(
        sqs,
        queue_url,
        until=lambda got: any(
            r["detail"].get("event") == "pullRequestStatusChanged" for r in got
        ),
        timeout_s=_DELIVERY_TIMEOUT_S,
        reason=(
            "the pullRequestStatusChanged event for the closed pull request to arrive; it was "
            "emitted last, so its arrival bounds the window every earlier event had"
        ),
    )

    by_event: dict[str, list[dict]] = {}
    for record in records:
        by_event.setdefault(record["detail"].get("event"), []).append(record)

    for expected_event in (
        "pullRequestCreated",
        "pullRequestSourceBranchUpdated",
        "pullRequestStatusChanged",
    ):
        assert expected_event in by_event, (
            f"no {expected_event!r} event arrived on the queue within "
            f"{_DELIVERY_TIMEOUT_S}s. Events that did arrive: "
            f"{sorted(k for k in by_event if k)!r}"
        )

    for record in records:
        assert record["source"] == "aws.codecommit", (
            f"a delivered record reports source {record['source']!r}, expected 'aws.codecommit'"
        )
        assert record["detail-type"] == "CodeCommit Pull Request State Change", (
            f"a delivered record reports detail-type {record['detail-type']!r}, expected "
            f"'CodeCommit Pull Request State Change'"
        )
        assert record["resources"] == [watched["Arn"]], (
            f"a delivered record reports resources {record['resources']!r}, expected exactly "
            f"[{watched['Arn']!r}] -- the rule pattern matched on this field, so anything else "
            f"means the scoping is accidental"
        )
        assert record["account"] == account, (
            f"a delivered record reports account {record['account']!r}, expected the caller's "
            f"account {account!r}"
        )
        assert record["region"] == ctx.region, (
            f"a delivered record reports region {record['region']!r}, expected {ctx.region!r}"
        )
        assert record["detail"]["pullRequestId"] == pr_id, (
            f"a delivered record names pullRequestId {record['detail']['pullRequestId']!r}, "
            f"expected {pr_id!r}"
        )
        assert watched_name in record["detail"]["repositoryNames"], (
            f"a delivered record reports repositoryNames "
            f"{record['detail']['repositoryNames']!r}, which does not contain {watched_name!r}"
        )

    # The created event's commit ids and status are the ones the API reported. The status casing
    # is normalised deliberately: the event is documented as 'Open' and the API returns 'OPEN'.
    created = by_event["pullRequestCreated"][0]["detail"]
    assert created["destinationCommit"] == base, (
        f"pullRequestCreated reports destinationCommit {created['destinationCommit']!r}, "
        f"expected the destination tip the API resolved, {base!r}"
    )
    assert created["sourceCommit"] == first_source, (
        f"pullRequestCreated reports sourceCommit {created['sourceCommit']!r}, expected the "
        f"source tip at creation, {first_source!r}"
    )
    assert created["pullRequestStatus"].upper() == api_open_status.upper(), (
        f"pullRequestCreated reports pullRequestStatus {created['pullRequestStatus']!r}; "
        f"CreatePullRequest reported {api_open_status!r} (compared case-insensitively)"
    )

    # The source-branch-update event must name the NEW tip, not the old one. This is the field
    # a target is most likely to copy from the pull request record instead of the ref update.
    updated = by_event["pullRequestSourceBranchUpdated"][0]["detail"]
    assert updated["sourceCommit"] == second_source, (
        f"pullRequestSourceBranchUpdated reports sourceCommit {updated['sourceCommit']!r}, "
        f"expected the second feature commit {second_source!r} (the tip before the update was "
        f"{first_source!r})"
    )

    status_changed = by_event["pullRequestStatusChanged"][0]["detail"]
    assert status_changed["pullRequestStatus"].upper() == api_closed_status.upper(), (
        f"pullRequestStatusChanged reports pullRequestStatus "
        f"{status_changed['pullRequestStatus']!r}; UpdatePullRequestStatus reported "
        f"{api_closed_status!r} (compared case-insensitively)"
    )

    delivered_pr_ids = {r["detail"].get("pullRequestId") for r in records}
    assert ignored_pr_id not in delivered_pr_ids, (
        f"the pull request in the unmatched repository ({ignored_pr_id!r}) was delivered; the "
        f"rule pattern pins resources to {watched['Arn']!r}, so it cannot match by "
        f"construction. Delivered pull request ids: {sorted(i for i in delivered_pr_ids if i)!r}"
    )
    delivered_arns = {tuple(r["resources"]) for r in records}
    assert delivered_arns == {(watched["Arn"],)}, (
        f"records arrived for resources {sorted(delivered_arns)!r}; only "
        f"[{watched['Arn']!r}] can match this rule"
    )



def _drain_until(sqs, queue_url, *, until, timeout_s: float, reason: str) -> list[dict]:
    """Long-poll the queue, returning every EventBridge event body once ``until`` holds.

    RAISES on expiry naming what it was waiting for and what it collected.
    """
    collected: list[dict] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        received = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10
        )
        for message in received.get("Messages", []):
            # An EventBridge SQS target delivers the event envelope as the raw message body.
            collected.append(json.loads(message["Body"]))
            sqs.delete_message(
                QueueUrl=queue_url, ReceiptHandle=message["ReceiptHandle"]
            )
        if until(collected):
            return collected
    raise AssertionError(
        f"waited {timeout_s}s for {reason} and it never happened. Collected "
        f"{len(collected)} record(s): "
        f"{[(r.get('detail-type'), r.get('detail', {}).get('event')) for r in collected]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
