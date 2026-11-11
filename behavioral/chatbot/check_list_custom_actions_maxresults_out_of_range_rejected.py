"""list-custom-actions-maxresults-out-of-range-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-custom-actions-maxresults-out-of-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["chatbot"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListCustomActions with MaxResults 0 and 101 (sent with client-side validation off) fails with
    InvalidRequestException "Invalid request body", while MaxResults 50 returns a CustomActions list."""
    from botocore.config import Config

    chatbot = ctx.client("chatbot")
    unvalidated = ctx.client("chatbot", config=Config(parameter_validation=False))

    code_low, message_low = _error(lambda: unvalidated.list_custom_actions(MaxResults=0))
    assert code_low == "InvalidRequestException", f"unexpected code={code_low!r}"
    assert message_low == "Invalid request body", f"unexpected message={message_low!r}"

    code_high, message_high = _error(lambda: unvalidated.list_custom_actions(MaxResults=101))
    assert code_high == "InvalidRequestException", f"unexpected code={code_high!r}"
    assert message_high == "Invalid request body", f"unexpected message={message_high!r}"

    resp = chatbot.list_custom_actions(MaxResults=50)
    assert isinstance(resp["CustomActions"], list)


def _error(fn):
    """Call fn(); return the (code, message) it is refused with. An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a refusal, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
