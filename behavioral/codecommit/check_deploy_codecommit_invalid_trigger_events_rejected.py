"""deploy-codecommit-invalid-trigger-events-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "deploy-codecommit-invalid-trigger-events-rejected"
GROUP = "error-semantics"
SERVICES = ["codecommit"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutRepositoryTriggers with "all" combined with another event raises
    InvalidRepositoryTriggerEventsException and leaves no trigger, while a valid "all" trigger applies."""
    codecommit = ctx.client("codecommit")
    repo_name = ctx.unique_name("sim2real-behav-trignegrepo-")
    codecommit.create_repository(repositoryName=repo_name, tags={"sim2real": "trignegrepo"})
    ctx.on_cleanup(lambda: codecommit.delete_repository(repositoryName=repo_name))

    fake_destination_arn = f"arn:aws:sns:{ctx.region}:111122223333:sim2real-nonexistent-topic"

    # Baseline: no triggers configured yet.
    baseline = codecommit.get_repository_triggers(repositoryName=repo_name)
    assert baseline["triggers"] == [], f"expected no triggers on a fresh repo, got {baseline['triggers']!r}"

    # Break exactly one thing: "all" combined with another event is invalid.
    bad_trigger = {
        "name": "bad-trigger",
        "destinationArn": fake_destination_arn,
        "events": ["all", "updateReference"],
        "branches": [],
    }
    code, message = _error(
        lambda: codecommit.put_repository_triggers(
            repositoryName=repo_name, triggers=[bad_trigger]
        )
    )
    assert code == "InvalidRepositoryTriggerEventsException", (
        f"expected InvalidRepositoryTriggerEventsException for events=['all', 'updateReference'], "
        f"got {code!r}"
    )
    expected = (
        "Repository trigger events cannot contain 'all' and additional event types "
        "simultaneously"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the repository still has no trigger configuration.
    after_bad = codecommit.get_repository_triggers(repositoryName=repo_name)
    assert after_bad["triggers"] == [], (
        f"the rejected PutRepositoryTriggers still left triggers configured: {after_bad['triggers']!r}"
    )

    # Positive control: the same-shaped call with a single valid event succeeds.
    good_trigger = {
        "name": "good-trigger",
        "destinationArn": fake_destination_arn,
        "events": ["all"],
        "branches": [],
    }
    put_resp = codecommit.put_repository_triggers(
        repositoryName=repo_name, triggers=[good_trigger]
    )
    assert put_resp["configurationId"], (
        f"expected a non-empty configurationId from a valid PutRepositoryTriggers, got {put_resp!r}"
    )

    after_good = codecommit.get_repository_triggers(repositoryName=repo_name)
    assert len(after_good["triggers"]) == 1, (
        f"expected exactly 1 trigger after the valid PutRepositoryTriggers, got {after_good['triggers']!r}"
    )
    assert after_good["triggers"][0]["name"] == "good-trigger", (
        f"expected trigger name 'good-trigger', got {after_good['triggers'][0]['name']!r}"
    )
    assert after_good["triggers"][0]["events"] == ["all"], (
        f"expected trigger events ['all'], got {after_good['triggers'][0]['events']!r}"
    )


def _error(fn):
    """Call fn(); return its error (code, message). A call that succeeds raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
