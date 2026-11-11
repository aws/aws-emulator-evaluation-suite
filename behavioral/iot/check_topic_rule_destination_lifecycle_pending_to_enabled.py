"""topic-rule-destination-lifecycle-pending-to-enabled."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "topic-rule-destination-lifecycle-pending-to-enabled"
GROUP = "state-machine"
SERVICES = ["iot"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A topic rule destination starts IN_PROGRESS (awaiting confirmation), rejects a
    confirmation with an invalid token without changing state, and is removed from the
    account's listing once deleted."""
    iot = ctx.client("iot")
    confirmation_url = f"https://example.com/sim2real-iot/{ctx.unique_name('confirm-')}"
    created = iot.create_topic_rule_destination(
        destinationConfiguration={"httpUrlConfiguration": {"confirmationUrl": confirmation_url}}
    )["topicRuleDestination"]
    arn = created["arn"]
    ctx.on_cleanup(lambda: _delete_destination_quiet(iot, arn))

    assert created["status"] == "IN_PROGRESS", f"expected IN_PROGRESS on create, got {created['status']!r}"

    got_status = _list_status(iot, arn)
    assert got_status == "IN_PROGRESS", f"expected IN_PROGRESS in listing, got {got_status!r}"

    # Empirical access-control fact: GetTopicRuleDestination on a brand-new, unconfirmed
    # HTTP destination can transiently deny even the creator/owner with
    # UnauthorizedException for a short window after creation (unlike the account-wide,
    # non-resource-scoped ListTopicRuleDestinations, which is unaffected) -- so Get is
    # retried past that specific error, and List is used as the primary state source.
    got = _retry_while(
        lambda: iot.get_topic_rule_destination(arn=arn)["topicRuleDestination"],
        retry_codes={"UnauthorizedException"},
        timeout_s=60.0,
        interval_s=5.0,
    )
    assert got["status"] == "IN_PROGRESS", f"expected IN_PROGRESS via Get, got {got['status']!r}"
    assert got["httpUrlProperties"]["confirmationUrl"] == confirmation_url, (
        f"expected confirmationUrl {confirmation_url!r}, got {got['httpUrlProperties']['confirmationUrl']!r}"
    )

    # Confirming with a token we never received (it was never delivered to us) must be
    # rejected, and must NOT flip the destination to ENABLED.
    code, message = _error_code(
        lambda: iot.confirm_topic_rule_destination(confirmationToken="bogus-token-never-issued")
    )
    assert code == "InvalidRequestException", f"expected InvalidRequestException for a bogus token, got {code!r}"
    assert message == "Invalid confirmation token.", f"expected 'Invalid confirmation token.', got {message!r}"
    still_pending = _list_status(iot, arn)
    assert still_pending == "IN_PROGRESS", f"expected status to stay IN_PROGRESS, got {still_pending!r}"

    iot.delete_topic_rule_destination(arn=arn)
    # DELETING is transient: poll until the destination is gone from the listing.
    final_status = _poll_until(
        lambda: _list_status(iot, arn),
        lambda s: s is None,
        timeout_s=120.0,
        interval_s=3.0,
    )
    assert final_status is None, (
        f"expected the destination gone from the listing after delete, got {final_status!r}"
    )


def _error_code(fn):
    """Return (code, message) of the ClientError fn() raises; fail loudly if it succeeds."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, call succeeded with {result!r}")


def _retry_while(fn, retry_codes, timeout_s=20.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in retry_codes and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _list_status(iot, arn):
    next_token = None
    for _ in range(50):
        kwargs = {"nextToken": next_token} if next_token else {}
        page = iot.list_topic_rule_destinations(**kwargs)
        for summary in page.get("destinationSummaries", []):
            if summary["arn"] == arn:
                return summary["status"]
        next_token = page.get("nextToken")
        if not next_token:
            break
    return None


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _delete_destination_quiet(iot, arn):
    """Teardown: a destination gone from (or DELETING in) the listing is clean; any refusal raises."""
    if _list_status(iot, arn) in (None, "DELETING"):
        return
    try:
        iot.delete_topic_rule_destination(arn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
