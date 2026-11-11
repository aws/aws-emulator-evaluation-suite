"""sms-sandbox-delete-unknown-number."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError


from behavioral_harness import tags

CHECK = "sms-sandbox-delete-unknown-number"
GROUP = 'error-semantics'
SERVICES = ['sns']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteSMSSandboxPhoneNumber on a never-added number raises ResourceNotFound "Resource does not exist";
    a number that lands in the sandbox list deletes, disappears, and a second delete gets the same error,
    while a Create that lands nothing must be the UserError "No origination entities available to send"."""
    sns = ctx.client("sns")
    suffix = uuid.uuid4().int % 10000
    known_number = f"+1500555{suffix:04d}"
    never_added_number = f"+1500556{suffix:04d}"

    listed = _listed_numbers(sns)
    if known_number in listed or never_added_number in listed:
        raise AssertionError(f"test numbers already present in the sandbox list: {listed}")

    ctx.on_cleanup(lambda: _best_effort_delete(sns, known_number))

    create_error = None
    try:
        sns.create_sms_sandbox_phone_number(PhoneNumber=known_number)
    except ClientError as exc:
        error = exc.response.get("Error", {})
        code, message = error.get("Code"), error.get("Message", "")
        if code == "UserError" and "no origination entities available" in message.lower():
            create_error = (code, message)
        else:
            raise

    landed = known_number in _listed_numbers(sns)

    if landed:
        # Without an origination entity, Create raises a UserError yet AWS still enqueues the
        # Pending sandbox entry, so the positive control keys off the list, not off Create.
        sns.delete_sms_sandbox_phone_number(PhoneNumber=known_number)
        after_delete = _listed_numbers(sns)
        assert known_number not in after_delete, (
            f"{known_number} still present in sandbox list after delete"
        )

        # Negative, same identifier: once removed from the sandbox, delete must be rejected.
        code, message = _delete_error(sns, known_number)
        assert code == "ResourceNotFound", (
            f"expected ResourceNotFound re-deleting a number just removed from the sandbox, got {code!r}"
        )
        assert message == "Resource does not exist", (
            f"unexpected ResourceNotFound message re-deleting {known_number}: {message!r}"
        )
    elif create_error is not None:
        # Create had no effect: it must be the documented origination-entity refusal.
        assert create_error == ("UserError", "No origination entities available to send"), (
            f"unexpected CreateSMSSandboxPhoneNumber refusal: {create_error!r}"
        )
    else:
        raise AssertionError(
            f"{known_number} missing from sandbox list after a Create that raised no error"
        )

    # Negative, never-added identifier: the same specific error, not a family of failures,
    # and unaffected by the origination-entity gate (delete needs no origination entity).
    code, message = _delete_error(sns, never_added_number)
    assert code == "ResourceNotFound", (
        f"expected ResourceNotFound deleting a number that was never added to the sandbox, got {code!r}"
    )
    assert message == "Resource does not exist", (
        f"unexpected ResourceNotFound message deleting {never_added_number}: {message!r}"
    )


def _listed_numbers(sns) -> set[str]:
    numbers: set[str] = set()
    next_token = None
    while True:
        kwargs = {"NextToken": next_token} if next_token else {}
        resp = sns.list_sms_sandbox_phone_numbers(**kwargs)
        numbers.update(n["PhoneNumber"] for n in resp.get("PhoneNumbers", []))
        next_token = resp.get("NextToken")
        if not next_token:
            return numbers


def _delete_error(sns, phone_number: str) -> tuple[str | None, str | None]:
    try:
        sns.delete_sms_sandbox_phone_number(PhoneNumber=phone_number)
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"delete of {phone_number} unexpectedly succeeded")


def _best_effort_delete(sns, phone_number: str) -> None:
    try:
        sns.delete_sms_sandbox_phone_number(PhoneNumber=phone_number)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
