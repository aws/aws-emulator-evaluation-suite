"""receipt-rule-set-delete-while-active-rejected."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "receipt-rule-set-delete-while-active-rejected"
GROUP = "overly-permissive"
SERVICES = ["ses"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:ses-active-receipt-rule-set")
def run(ctx) -> None:
    """DeleteReceiptRuleSet on the active rule set fails with CannotDelete and leaves it in place; once
    deactivated the delete succeeds, and describing or activating the deleted set is rejected."""
    ses = ctx.client("ses")
    rule_set_name = ctx.unique_name("sim2real-ses-rrs-")
    ses.create_receipt_rule_set(RuleSetName=rule_set_name)

    previous_active = _active_rule_set_name(ses)

    def _restore_active() -> None:
        if previous_active:
            ses.set_active_receipt_rule_set(RuleSetName=previous_active)
        else:
            ses.set_active_receipt_rule_set()

    ctx.on_cleanup(_restore_active)
    ctx.on_cleanup(lambda: _best_effort_delete(ses, rule_set_name))

    ses.set_active_receipt_rule_set(RuleSetName=rule_set_name)

    code, status, message = _error_code(lambda: ses.delete_receipt_rule_set(RuleSetName=rule_set_name))
    assert code == "CannotDelete", (
        f"expected CannotDelete deleting the active rule set {rule_set_name!r}, got {code!r}"
    )
    assert status == 400, f"expected HTTP 400 for CannotDelete, got {status!r}"
    assert rule_set_name in message, f"expected the CannotDelete message to name {rule_set_name!r}, got {message!r}"

    names = [r["Name"] for r in ses.list_receipt_rule_sets().get("RuleSets", [])]
    assert rule_set_name in names, (
        f"the rejected delete removed {rule_set_name!r} from ListReceiptRuleSets: {names!r}"
    )

    _restore_active()
    ses.delete_receipt_rule_set(RuleSetName=rule_set_name)
    names_after = [r["Name"] for r in ses.list_receipt_rule_sets().get("RuleSets", [])]
    assert rule_set_name not in names_after, (
        f"{rule_set_name!r} still listed by ListReceiptRuleSets after the delete succeeded"
    )

    describe_code, status, message = _error_code(
        lambda: ses.describe_receipt_rule_set(RuleSetName=rule_set_name)
    )
    assert describe_code == "RuleSetDoesNotExist", (
        f"expected RuleSetDoesNotExist describing the deleted rule set {rule_set_name!r}, "
        f"got {describe_code!r}"
    )
    assert status == 400, f"expected HTTP 400 for RuleSetDoesNotExist, got {status!r}"
    expected_message = f"Rule set does not exist: {rule_set_name}"
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

    activate_code, status, message = _error_code(
        lambda: ses.set_active_receipt_rule_set(RuleSetName=rule_set_name)
    )
    assert activate_code == "RuleSetDoesNotExist", (
        f"expected RuleSetDoesNotExist activating the deleted rule set {rule_set_name!r}, "
        f"got {activate_code!r}"
    )
    assert status == 400, f"expected HTTP 400 for RuleSetDoesNotExist, got {status!r}"
    expected_message = f"Rule set does not exist: {rule_set_name}"
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"




def _active_rule_set_name(ses: Any) -> str | None:
    resp = ses.describe_active_receipt_rule_set()
    metadata = resp.get("Metadata") or {}
    return metadata.get("Name")


def _best_effort_delete(ses: Any, rule_set_name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        ses.delete_receipt_rule_set(RuleSetName=rule_set_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "RuleSetDoesNotExist":
            raise


def _error_code(fn: Callable[[], Any]) -> tuple:
    """Return the (Code, HTTP status, Message) of the ClientError fn() raises; raise on success."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return (
            err.response["Error"]["Code"],
            err.response.get("ResponseMetadata", {}).get("HTTPStatusCode"),
            err.response["Error"].get("Message") or "",
        )
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
