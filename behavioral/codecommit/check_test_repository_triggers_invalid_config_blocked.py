"""test-repository-triggers-invalid-config-blocked."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "test-repository-triggers-invalid-config-blocked"
GROUP = "overly-permissive"
SERVICES = ["codecommit"]


@tags("axis:negative-delivery", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """TestRepositoryTriggers reports a trigger whose SNS topic does not exist as failed, while
    a real same-account topic succeeds, and creating the missing topic makes the identical
    trigger config succeed."""
    codecommit = ctx.client("codecommit")
    sns = ctx.client("sns")
    sts = ctx.client("sts")

    repo_name = ctx.unique_name("sim2real-behav-repo-")
    tags_kw = {"sim2real": "cc-trig-invalid-config"}
    codecommit.create_repository(repositoryName=repo_name, tags=tags_kw)
    ctx.on_cleanup(lambda: codecommit.delete_repository(repositoryName=repo_name))

    account_id = sts.get_caller_identity()["Account"]
    bogus_topic_name = ctx.unique_name("sim2real-behav-notopic-")
    bogus_arn = f"arn:aws:sns:{ctx.region}:{account_id}:{bogus_topic_name}"

    bad_trigger = {
        "name": "bad-trigger",
        "destinationArn": bogus_arn,
        "events": ["all"],
        "branches": [],
    }
    codecommit.put_repository_triggers(repositoryName=repo_name, triggers=[bad_trigger])
    bad_result = codecommit.test_repository_triggers(
        repositoryName=repo_name, triggers=[bad_trigger]
    )
    assert bad_result["successfulExecutions"] == []
    assert len(bad_result["failedExecutions"]) == 1
    failure = bad_result["failedExecutions"][0]
    assert failure["trigger"] == "bad-trigger"
    message = failure["failureMessage"]
    assert "does not exist" in message.lower(), (
        f"expected a missing-destination failure message, got {message!r}"
    )

    # Positive control: a real same-account SNS topic (needs no extra resource policy).
    topic_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-behav-topic-"),
        Tags=[{"Key": "sim2real", "Value": "cc-trig-invalid-config"}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))
    good_trigger = {
        "name": "good-trigger",
        "destinationArn": topic_arn,
        "events": ["all"],
        "branches": [],
    }
    codecommit.put_repository_triggers(repositoryName=repo_name, triggers=[good_trigger])
    good_result = codecommit.test_repository_triggers(
        repositoryName=repo_name, triggers=[good_trigger]
    )
    assert good_result["failedExecutions"] == []
    assert good_result["successfulExecutions"] == ["good-trigger"]

    # Restore: create the exact topic the still-configured "bad-trigger" points at,
    # then retest the identical trigger config and demand it now succeeds.
    restored_arn = sns.create_topic(
        Name=bogus_topic_name,
        Tags=[{"Key": "sim2real", "Value": "cc-trig-invalid-config"}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=restored_arn))
    assert restored_arn == bogus_arn
    restored_result = codecommit.test_repository_triggers(
        repositoryName=repo_name, triggers=[bad_trigger]
    )
    assert restored_result["failedExecutions"] == []
    assert restored_result["successfulExecutions"] == ["bad-trigger"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
