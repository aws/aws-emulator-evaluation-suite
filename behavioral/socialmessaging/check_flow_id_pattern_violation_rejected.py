"""flow-id-pattern-violation-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "flow-id-pattern-violation-rejected"
GROUP = "validation"
SERVICES = ["socialmessaging"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetWhatsAppFlow rejects a non-numeric flowId with ValidationException before looking up the
    nonexistent WABA, and a numeric flowId on that WABA fails with ResourceNotFoundException "Id
    not found for account."; a linked WABA's first flow, if any, is returned."""
    sm = ctx.client("socialmessaging")
    waba_id = "waba-00000000000000000000000000000000"

    code, msg = _error(lambda: sm.get_whatsapp_flow(id=waba_id, flowId="not-numeric"))
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected_msg = "1 validation error detected: Value 'not-numeric' at 'flowId' failed to satisfy constraint: Member must satisfy regular expression pattern: [0-9]+"
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    code2, msg2 = _error(lambda: sm.get_whatsapp_flow(id=waba_id, flowId="123456789012"))
    assert code2 == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code2}"
    expected_msg2 = 'Id not found for account.'
    assert msg2 == expected_msg2, f"expected message {expected_msg2!r}, got {msg2!r}"

    linked = sm.list_linked_whatsapp_business_accounts().get("linkedAccounts", [])
    if linked:
        real_waba_id = linked[0]["id"]
        flows = sm.list_whatsapp_flows(id=real_waba_id).get("flows", [])
        if flows:
            real_flow_id = flows[0]["flowId"]
            try:
                sm.get_whatsapp_flow(id=real_waba_id, flowId=real_flow_id)
            except ClientError as exc:
                real_code = exc.response.get("Error", {}).get("Code")
                raise AssertionError(
                    f"expected a real linked flow id ({real_flow_id!r}) to be "
                    f"accepted, got {real_code}"
                ) from exc


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
