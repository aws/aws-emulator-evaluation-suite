"""dataset-id-below-min-length-rejected."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "dataset-id-below-min-length-rejected"
GROUP = "validation"
SERVICES = ["socialmessaging"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """With client-side validation off, SendWhatsAppConversionEvent rejects a 3-digit datasetId
    (below the 10-20 digit range) with ValidationException at the service, while a 10-digit
    datasetId passes validation and fails with ResourceNotFoundException, each with its exact message."""
    sm = ctx.client("socialmessaging")
    sm_unvalidated = ctx.client("socialmessaging", config=Config(parameter_validation=False))
    waba_id = "waba-00000000000000000000000000000000"
    event_data = b'{"event_name":"Purchase"}'

    code, msg = _error(
        lambda: sm_unvalidated.send_whatsapp_conversion_event(
            id=waba_id, datasetId="123", eventData=event_data
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected_msg = "1 validation error detected: Value '123' at 'datasetId' failed to satisfy constraint: Member must have length greater than or equal to 10"
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
