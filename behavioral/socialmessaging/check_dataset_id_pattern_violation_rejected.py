"""dataset-id-pattern-violation-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "dataset-id-pattern-violation-rejected"
GROUP = "validation"
SERVICES = ["socialmessaging"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SendWhatsAppConversionEvent rejects a datasetId containing letters with ValidationException,
    while an all-digit datasetId of valid length fails with ResourceNotFoundException because
    neither the WABA nor the dataset exists, each with its exact message."""
    sm = ctx.client("socialmessaging")
    waba_id = "waba-00000000000000000000000000000000"
    event_data = b'{"event_name":"Purchase"}'

    code, msg = _error(
        lambda: sm.send_whatsapp_conversion_event(
            id=waba_id, datasetId="abc1234567", eventData=event_data
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected_msg = "1 validation error detected: Value 'abc1234567' at 'datasetId' failed to satisfy constraint: Member must satisfy regular expression pattern: [0-9]+"
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    code2, msg2 = _error(
        lambda: sm.send_whatsapp_conversion_event(
            id=waba_id, datasetId="1234567890", eventData=event_data
        )
    )
    assert code2 == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code2}"
    expected_msg2 = 'Id not found for account.'
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
