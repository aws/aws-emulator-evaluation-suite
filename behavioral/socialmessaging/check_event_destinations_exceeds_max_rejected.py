"""event-destinations-exceeds-max-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "event-destinations-exceeds-max-rejected"
GROUP = "overly-permissive"
SERVICES = ["socialmessaging"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutWhatsAppBusinessAccountEventDestinations rejects two event destinations (the maximum is
    one) with ValidationException, while exactly one passes that check and fails with
    AccessDeniedException for a roleArn in another account, each with its exact message."""
    sm = ctx.client("socialmessaging")
    waba_id = "waba-00000000000000000000000000000000"
    role_arn = "arn:aws:iam::111122223333:role/sim2real-behav-fake-role"
    dest1 = {
        "eventDestinationArn": "arn:aws:sns:us-east-1:111122223333:sim2real-topic-1",
        "roleArn": role_arn,
    }
    dest2 = {
        "eventDestinationArn": "arn:aws:sns:us-east-1:111122223333:sim2real-topic-2",
        "roleArn": role_arn,
    }

    code, msg = _error(
        lambda: sm.put_whatsapp_business_account_event_destinations(
            id=waba_id, eventDestinations=[dest1, dest2]
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    rendered = ", ".join(
        "WhatsAppBusinessAccountEventDestination("
        f"eventDestinationArn={d['eventDestinationArn']}, roleArn={d['roleArn']})"
        for d in (dest1, dest2)
    )
    expected_msg = (
        f"1 validation error detected: Value '[{rendered}]' at 'eventDestinations' "
        "failed to satisfy constraint: Member must have length less than or equal to 1"
    )
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    code2, msg2 = _error(
        lambda: sm.put_whatsapp_business_account_event_destinations(
            id=waba_id, eventDestinations=[dest1]
        )
    )
    assert code2 == "AccessDeniedException", f"expected AccessDeniedException, got {code2}"
    expected_msg2 = 'Cross-account pass role is not allowed.'
    assert msg2 == expected_msg2, f"expected message {expected_msg2!r}, got {msg2!r}"


def _error(fn):
    """Call fn(); return the (code, message) of its botocore error. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
