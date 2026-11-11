"""concurrent-topic-rule-destination-update-conflicting-rejected."""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-topic-rule-destination-update-conflicting-rejected"
GROUP = "concurrency"
SERVICES = ["iot"]

_CONFLICT_MESSAGE = "This destination is being modified by another request"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two concurrent UpdateTopicRuleDestination calls on one unconfirmed HTTP destination: at least
    one succeeds, a loser is refused only with ConflictingResourceUpdateException and its exact
    message, and the destination's lastUpdatedAt advances."""
    iot = ctx.client("iot")
    confirmation_url = f"https://{ctx.unique_name('sim2real-ttrd')}.example.com/confirm"
    dest = iot.create_topic_rule_destination(
        destinationConfiguration={"httpUrlConfiguration": {"confirmationUrl": confirmation_url}}
    )["topicRuleDestination"]
    arn = dest["arn"]
    ctx.on_cleanup(lambda: _safe_delete(iot, arn))
    # note: IoT's TagResource rejects ruledestination ARNs (InvalidRequestException) --
    # topic rule destinations are not a taggable resource type.

    baseline = iot.get_topic_rule_destination(arn=arn)["topicRuleDestination"]

    successes, failures = _race_once(iot, arn)
    assert successes, f"expected at least one racer to succeed, got failures {failures}"
    # An overlapping update may be refused; serialized updates both succeed.
    assert all(f == ("ConflictingResourceUpdateException", _CONFLICT_MESSAGE) for f in failures), (
        f"a losing racer must get ConflictingResourceUpdateException with its exact message, got {failures}"
    )

    # independent read at the destination: an accepted update landed there.
    after_race = iot.get_topic_rule_destination(arn=arn)["topicRuleDestination"]
    assert after_race["lastUpdatedAt"] != baseline["lastUpdatedAt"], (
        "lastUpdatedAt did not advance after the race: "
        f"still {baseline['lastUpdatedAt']!r}"
    )

    # positive control: once contention has cleared, a solo update on the same
    # destination still succeeds -- the destination isn't left stuck by the race --
    # and an independent read confirms the effect actually landed.
    iot.update_topic_rule_destination(arn=arn, status="IN_PROGRESS")
    final = iot.get_topic_rule_destination(arn=arn)["topicRuleDestination"]
    assert final["lastUpdatedAt"] != after_race["lastUpdatedAt"], (
        "solo update after contention cleared did not advance lastUpdatedAt: "
        f"still {after_race['lastUpdatedAt']!r}"
    )


# ===== helpers =====

def _race_once(iot, arn: str):
    barrier = threading.Barrier(2)

    def _attempt():
        barrier.wait()
        try:
            iot.update_topic_rule_destination(arn=arn, status="IN_PROGRESS")
            return ("ok", None)
        except ClientError as e:
            return ("err", (e.response["Error"]["Code"], e.response["Error"].get("Message")))

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = [f.result() for f in [pool.submit(_attempt) for _ in range(2)]]

    successes = [r for r in results if r[0] == "ok"]
    failures = [r[1] for r in results if r[0] == "err"]
    return successes, failures


def _safe_delete(iot, arn: str, timeout_s: float = 60.0) -> None:
    """Delete the destination, retrying while an update still holds it; raise any other failure."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            iot.delete_topic_rule_destination(arn=arn)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictingResourceUpdateException" or time.monotonic() >= deadline:
                raise
            time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
