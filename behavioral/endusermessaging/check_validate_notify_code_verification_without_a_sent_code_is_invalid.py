"""validate-notify-code-verification-without-a-sent-code-is-invalid."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "validate-notify-code-verification-without-a-sent-code-is-invalid"
GROUP = "notify-code-verifications"
SERVICES = ["endusermessaging"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError ``fn`` raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ValidateNotifyCodeVerification for a destination that was never sent a passcode answers
    status INVALID rather than an error, with or without a referenceId.
    """
    eum = ctx.client("endusermessaging")
    destination = "+12065550142"
    plain = eum.validate_notify_code_verification(destinationIdentity=destination, code="123456")
    assert plain["status"] == "INVALID", f"without referenceId, got {plain['status']!r}"
    referenced = eum.validate_notify_code_verification(
        destinationIdentity=destination, code="482913",
        referenceId=ctx.unique_name("sim2real-behav-eum-ref-"))
    assert referenced["status"] == "INVALID", f"with referenceId, got {referenced['status']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
