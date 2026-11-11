"""a-commit-refused-for-a-stale-parent-moves-no-reference-and-emits-no-state-change-event."""

from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "a-commit-refused-for-a-stale-parent-moves-no-reference-and-emits-no-state-change-event"
GROUP = "event-propagation"
SERVICES = ["codecommit", "events", "sqs"]

_BRANCH = "main"
_REF = "refs/heads/main"
_DETAIL_TYPE = "CodeCommit Repository State Change"
_STALE_PARENT_MESSAGE = (
    "The parent commit ID is not valid because it is not the current tip of the branch. You must "
    "provide the commit ID for the tip of the branch. The most common reason for this error is that "
    "your local repository is not synchronized to the latest changes in the AWS CodeCommit "
    "repository. Either synchronize your local repo by using the git pull command, or use GetBranch "
    "to retrieve the latest commit ID for the branch, and then try again."
)
#: Worst-case wall clock of the sequential polls below, declared so the suite timeout covers them.
_WORST_CASE_BUDGET_S = 1200


def _poll_until(probe, predicate, *, timeout_s, interval_s=3.0, description="condition"):
    """A bounded retry that RAISES on its deadline; never returns its last value on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _error(fn):
    """The AWS error (code, message) raised by fn(). RAISES if fn() unexpectedly SUCCEEDS."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("the call was expected to be rejected but it succeeded")


def _make_queue(ctx, name, check_tag):
    sqs = ctx.client("sqs")
    account = ctx.client("sts").get_caller_identity()["Account"]
    url = sqs.create_queue(QueueName=name, tags={"sim2real-check": check_tag})["QueueUrl"]
    ctx.on_cleanup(lambda u=url: ctx.client("sqs").delete_queue(QueueUrl=u))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    sqs.set_queue_attributes(
        QueueUrl=url,
        Attributes={
            "Policy": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "AllowEventBridge",
                            "Effect": "Allow",
                            "Principal": {"Service": "events.amazonaws.com"},
                            "Action": "sqs:SendMessage",
                            "Resource": arn,
                            "Condition": {
                                "ArnLike": {
                                    "aws:SourceArn": f"arn:*:events:{ctx.region}:{account}:rule/*"
                                }
                            },
                        }
                    ],
                }
            )
        },
    )
    return url, arn


def _drain(ctx, url, *, seconds):
    """Receive and delete every message that arrives within `seconds`, returning the bodies."""
    sqs = ctx.client("sqs")
    out = []
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            out.append(json.loads(msg["Body"]))
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
    return out


def _queue_depth(ctx, url):
    attrs = ctx.client("sqs").get_queue_attributes(
        QueueUrl=url,
        AttributeNames=[
            "ApproximateNumberOfMessages",
            "ApproximateNumberOfMessagesNotVisible",
            "ApproximateNumberOfMessagesDelayed",
        ],
    )["Attributes"]
    return sum(int(v) for v in attrs.values())


def _put_targets_ok(events, rule, targets):
    resp = events.put_targets(Rule=rule, Targets=targets)
    assert resp.get("FailedEntryCount") == 0, (
        f"put_targets on {rule} reported failures, so the wiring under test does not exist: "
        f"{resp.get('FailedEntries')!r}"
    )


def _teardown_rule(ctx, rule):
    events = ctx.client("events")
    events.remove_targets(Rule=rule, Ids=["q"], Force=True)
    events.delete_rule(Name=rule, Force=True)


def _state_change_events(messages, repo_arn):
    """Only this repository's reference-change events, so a sibling check's traffic cannot be mistaken
    for a leak (or hide one)."""
    return [
        m
        for m in messages
        if m.get("detail-type") == _DETAIL_TYPE and repo_arn in m.get("resources", [])
    ]


# ===== the check =====
@tags(
    "axis:negative-delivery",
    "cap:c2",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A commit refused for a stale parentCommitId leaves the branch tip unchanged and emits no
    repository-state-change event; retried against the current tip it emits one.

    Reference: https://docs.aws.amazon.com/codecommit/latest/userguide/monitoring-events.html
    Reference: https://docs.aws.amazon.com/codecommit/latest/APIReference/API_PutFile.html
    """
    cc = ctx.client("codecommit")
    events = ctx.client("events")
    check_tag = CHECK
    suffix = uuid.uuid4().hex[:10]

    repo = ctx.unique_name("sim2real-nd-cc-")
    created = cc.create_repository(
        repositoryName=repo,
        repositoryDescription="sim2real negative-delivery draft",
        tags={"sim2real-check": check_tag},
    )["repositoryMetadata"]
    ctx.on_cleanup(lambda: ctx.client("codecommit").delete_repository(repositoryName=repo))
    repo_arn = created["Arn"]

    queue_url, queue_arn = _make_queue(ctx, f"sim2real-nd-cc-{suffix}", check_tag)
    rule = ctx.unique_name("sim2real-nd-cc-rule-")
    events.put_rule(
        Name=rule,
        EventPattern=json.dumps(
            {
                "source": ["aws.codecommit"],
                "detail-type": [_DETAIL_TYPE],
                "resources": [repo_arn],
            }
        ),
        State="ENABLED",
        Tags=[{"Key": "sim2real-check", "Value": check_tag}],
    )
    ctx.on_cleanup(lambda: _teardown_rule(ctx, rule))
    _put_targets_ok(events, rule, [{"Id": "q", "Arn": queue_arn}])

    # The first commit CREATES the branch. Asserting `referenceCreated` here and `referenceUpdated`
    # below makes the `detail.event` literal falsifiable in both directions.
    t0 = time.monotonic()
    first = cc.put_file(
        repositoryName=repo,
        branchName=_BRANCH,
        fileContent=b"seed\n",
        filePath="seed.txt",
        commitMessage="seed",
    )
    creation = _poll_until(
        lambda: _state_change_events(_drain(ctx, queue_url, seconds=6), repo_arn),
        lambda evs: any(e["detail"].get("commitId") == first["commitId"] for e in evs),
        timeout_s=240,
        interval_s=0,
        description=(
            f"the branch-creating commit {first['commitId']} produced a '{_DETAIL_TYPE}' event on "
            f"{queue_url} — the positive control for the CodeCommit -> EventBridge -> SQS wiring"
        ),
    )
    latency = max(time.monotonic() - t0, 1.0)
    seed_event = next(e for e in creation if e["detail"]["commitId"] == first["commitId"])
    # AWS's documented example carries the
    # BARE branch name in `referenceName` and the full ref only in `referenceFullName` -- the two
    # are distinct fields, not one field spelled two ways.
    assert seed_event["detail"]["referenceName"] == _BRANCH, (
        f"the branch-creating event names referenceName={seed_event['detail']['referenceName']!r}, "
        f"expected the bare branch name {_BRANCH!r}"
    )
    assert seed_event["detail"]["referenceFullName"] == _REF, (
        f"the branch-creating event names referenceFullName="
        f"{seed_event['detail'].get('referenceFullName')!r}, expected {_REF!r}"
    )
    assert seed_event["detail"]["event"] == "referenceCreated", (
        f"the branch-creating event carries detail.event="
        f"{seed_event['detail']['event']!r}, expected 'referenceCreated' — a target that reports every "
        f"reference change identically fails here"
    )
    assert seed_event["source"] == "aws.codecommit", (
        f"the event carries source={seed_event['source']!r}, expected 'aws.codecommit'"
    )

    # The accepted update: same repository, rule and wiring, and it re-measures the latency.
    t1 = time.monotonic()
    second = cc.put_file(
        repositoryName=repo,
        branchName=_BRANCH,
        fileContent=b"one\n",
        filePath="one.txt",
        commitMessage="one",
        parentCommitId=first["commitId"],
    )
    update = _poll_until(
        lambda: _state_change_events(_drain(ctx, queue_url, seconds=6), repo_arn),
        lambda evs: any(e["detail"].get("commitId") == second["commitId"] for e in evs),
        timeout_s=240,
        interval_s=0,
        description=(
            f"the accepted update commit {second['commitId']} produced a '{_DETAIL_TYPE}' event — the "
            f"positive control immediately before the refusal"
        ),
    )
    # The larger of the two measured deliveries, not the smaller: the hold below must not be
    # sized against an optimistic latency, or a target that is merely slower than the FASTER of
    # the two controls reads as having withheld the event.
    latency = max(latency, time.monotonic() - t1, 1.0)
    upd = next(e for e in update if e["detail"]["commitId"] == second["commitId"])
    assert upd["detail"]["event"] == "referenceUpdated", (
        f"the update event carries detail.event={upd['detail']['event']!r}, expected "
        f"'referenceUpdated' for a branch that already existed"
    )
    tip_before = cc.get_branch(repositoryName=repo, branchName=_BRANCH)["branch"]["commitId"]
    assert tip_before == second["commitId"], (
        f"GetBranch reports tip {tip_before!r}, expected the accepted commit {second['commitId']!r} — "
        f"the freeze assertion below has nothing to hold constant otherwise"
    )

    # The refusal is structural: `first["commitId"]` is no longer the tip, so the write can
    # never be accepted, however long anything waits.
    refused_path = f"refused-{suffix}.txt"
    code, message = _error(
        lambda: ctx.client("codecommit").put_file(
            repositoryName=repo,
            branchName=_BRANCH,
            fileContent=b"stale\n",
            filePath=refused_path,
            commitMessage="stale parent",
            parentCommitId=first["commitId"],
        )
    )
    assert code == "ParentCommitIdOutdatedException", (
        f"put_file with a stale parentCommitId was refused with {code!r}, expected "
        f"'ParentCommitIdOutdatedException'"
    )
    assert message == _STALE_PARENT_MESSAGE, (
        f"put_file with a stale parentCommitId was refused with message {message!r}, expected "
        f"{_STALE_PARENT_MESSAGE!r}"
    )

    # The two structural second observables: the reference did not move and the content is absent.
    tip_after = cc.get_branch(repositoryName=repo, branchName=_BRANCH)["branch"]["commitId"]
    assert tip_after == tip_before, (
        f"GetBranch reports tip {tip_after!r} after the refused write, expected it unchanged at "
        f"{tip_before!r} — if the reference moved the write was not actually refused"
    )
    missing, missing_message = _error(
        lambda: ctx.client("codecommit").get_file(
            repositoryName=repo, commitSpecifier=_BRANCH, filePath=refused_path
        )
    )
    assert missing == "FileDoesNotExistException", (
        f"get_file on the refused path {refused_path!r} answered {missing!r}, expected "
        f"'FileDoesNotExistException' — the refused content must not be in the tree"
    )
    assert missing_message == f"Could not find path {refused_path}", (
        f"get_file on the refused path {refused_path!r} answered message {missing_message!r}, "
        f"expected {f'Could not find path {refused_path}'!r}"
    )

    # The negative: held for 3x the measured latency and confirmed by queue depth.
    hold = max(3 * latency, 15.0)
    leaked = _state_change_events(_drain(ctx, queue_url, seconds=hold), repo_arn)
    assert leaked == [], (
        f"{len(leaked)} '{_DETAIL_TYPE}' event(s) arrived for {repo} during a {hold:.0f}s hold (3x the "
        f"{latency:.0f}s measured latency) after a write that was REFUSED and moved no reference: "
        f"{[(e['detail'].get('event'), e['detail'].get('commitId')) for e in leaked]!r} — an event "
        f"naming a commit id GetCommit cannot resolve breaks every consumer that clones on it"
    )
    assert _queue_depth(ctx, queue_url) == 0, (
        f"the queue reports depth {_queue_depth(ctx, queue_url)} behind an empty receive — the second "
        f"independent observable disagrees with the first"
    )

    # Restore: the IDENTICAL write, against the current tip, is accepted AND emits the
    # event that was withheld.
    accepted = cc.put_file(
        repositoryName=repo,
        branchName=_BRANCH,
        fileContent=b"stale\n",
        filePath=refused_path,
        commitMessage="stale parent",
        parentCommitId=tip_after,
    )
    released = _poll_until(
        lambda: _state_change_events(_drain(ctx, queue_url, seconds=6), repo_arn),
        lambda evs: any(e["detail"].get("commitId") == accepted["commitId"] for e in evs),
        timeout_s=240,
        interval_s=0,
        description=(
            f"the same file and message, committed against the CURRENT tip, produced the "
            f"'{_DETAIL_TYPE}' event that was withheld"
        ),
    )
    ids = sorted({e["detail"]["commitId"] for e in released})
    assert ids == [accepted["commitId"]], (
        f"the queue carried events for commit ids {ids!r}, expected exactly "
        f"[{accepted['commitId']!r}] — the refused write must not produce a late event"
    )
    final = next(e for e in released if e["detail"]["commitId"] == accepted["commitId"])
    assert final["detail"]["event"] == "referenceUpdated", (
        f"the restored event carries detail.event={final['detail']['event']!r}, expected "
        f"'referenceUpdated'"
    )
    assert (
        cc.get_file(repositoryName=repo, commitSpecifier=_BRANCH, filePath=refused_path)[
            "fileContent"
        ]
        == b"stale\n"
    ), f"the accepted write did not put the expected bytes at {refused_path!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
