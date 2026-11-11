"""put-repository-triggers-invalid-destination-arn."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags

CHECK = "put-repository-triggers-invalid-destination-arn"
GROUP = 'overly-permissive'
SERVICES = ['codecommit']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutRepositoryTriggers with a malformed destination ARN raises
    InvalidRepositoryTriggerDestinationArnException and leaves the triggers unchanged, while
    a same-shaped valid trigger applies."""
    cc = ctx.client("codecommit")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    name = ctx.unique_name("sim2real-behav-repo-")
    cc.create_repository(repositoryName=name)
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=name))

    # Baseline: no triggers configured yet.
    baseline = cc.get_repository_triggers(repositoryName=name)
    assert baseline["triggers"] == [], f"expected no triggers before test, got {baseline['triggers']}"

    # Break exactly one thing: the destination ARN is not a valid ARN at all.
    bad_trigger = {
        "name": "bad-trigger",
        "destinationArn": "not-a-valid-sns-arn",
        "events": ["all"],
        "branches": [],
    }
    code, message = _error(
        lambda: cc.put_repository_triggers(repositoryName=name, triggers=[bad_trigger])
    )
    assert code == "InvalidRepositoryTriggerDestinationArnException", (
        f"expected InvalidRepositoryTriggerDestinationArnException, got {code}"
    )
    expected_message = "Repository trigger destination arn is incorrectly formatted"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the repository still has no trigger configuration.
    after_bad = cc.get_repository_triggers(repositoryName=name)
    assert after_bad["triggers"] == [], (
        f"expected trigger config unchanged (empty) after rejected put, got {after_bad['triggers']}"
    )

    # Positive control: a same-shaped call with a syntactically valid SNS ARN succeeds,
    # proving the rejection above is specific to the malformed ARN, not every call.
    good_arn = (
        f"arn:aws:sns:{ctx.region}:{account_id}:"
        f"{ctx.unique_name('sim2real-behav-notopic-')}"
    )
    good_trigger = {
        "name": "good-trigger",
        "destinationArn": good_arn,
        "events": ["all"],
        "branches": [],
    }
    put_resp = cc.put_repository_triggers(repositoryName=name, triggers=[good_trigger])
    assert put_resp["configurationId"], "expected a configurationId for the accepted trigger"

    after_good = cc.get_repository_triggers(repositoryName=name)
    assert len(after_good["triggers"]) == 1, (
        f"expected exactly 1 trigger after positive control, got {after_good['triggers']}"
    )
    assert after_good["triggers"][0]["name"] == "good-trigger", after_good["triggers"][0]
    assert after_good["triggers"][0]["destinationArn"] == good_arn, after_good["triggers"][0]


def _error(fn: Callable[[], Any]) -> tuple[str, str | None]:
    """Call fn() and return its ClientError (code, message); raise if the call succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
