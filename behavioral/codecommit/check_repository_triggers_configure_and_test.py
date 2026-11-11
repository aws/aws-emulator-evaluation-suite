"""repository-triggers-configure-and-test."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "repository-triggers-configure-and-test"
GROUP = "data-plane"
SERVICES = ["codecommit"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Triggers configured via PutRepositoryTriggers are returned unchanged by
    GetRepositoryTriggers, and TestRepositoryTriggers reports a genuine successful
    delivery against a real destination without mutating the stored configuration."""
    cc = ctx.client("codecommit")
    sns = ctx.client("sns")

    repo_name = ctx.unique_name("sim2real-cc-trigger-")
    cc.create_repository(repositoryName=repo_name)
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo_name))

    topic_name = ctx.unique_name("sim2real-cc-trigger-topic-")
    destination_arn = sns.create_topic(Name=topic_name)["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=destination_arn))

    trigger = {
        "name": "my-trigger",
        "destinationArn": destination_arn,
        "events": ["all"],
        "branches": [],
    }

    cc.put_repository_triggers(repositoryName=repo_name, triggers=[trigger])

    fetched = cc.get_repository_triggers(repositoryName=repo_name)["triggers"]
    assert len(fetched) == 1
    assert fetched[0]["name"] == trigger["name"]
    assert fetched[0]["destinationArn"] == destination_arn
    assert fetched[0]["events"] == ["all"]
    assert fetched[0].get("branches", []) == []

    test_result = cc.test_repository_triggers(repositoryName=repo_name, triggers=[trigger])
    assert test_result.get("successfulExecutions", []) == [trigger["name"]], (
        f"expected {trigger['name']!r} to succeed against a real SNS topic, "
        f"got successful={test_result.get('successfulExecutions')} "
        f"failed={test_result.get('failedExecutions')}"
    )
    assert test_result.get("failedExecutions", []) == [], test_result.get("failedExecutions")

    # TestRepositoryTriggers must not mutate the stored trigger configuration.
    fetched_after = cc.get_repository_triggers(repositoryName=repo_name)["triggers"]
    assert fetched_after == fetched


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
