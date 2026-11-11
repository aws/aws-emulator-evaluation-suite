"""list-sessions-out-of-range-maxresults-rejected."""
from __future__ import annotations

from botocore.client import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-sessions-out-of-range-maxresults-rejected"
GROUP = "overly-permissive"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """The service itself rejects ListSessions maxResults above 1000 and below 1 with ValidationException
    and the exact messages (client-side validation is off), while maxResults=1000 succeeds."""
    client = ctx.client("bedrock-agent-runtime")

    raw = ctx.client("bedrock-agent-runtime", config=Config(parameter_validation=False))

    code_high, message_high = _error(lambda: raw.list_sessions(maxResults=1001))
    assert code_high == "ValidationException", f"expected ValidationException, got {code_high!r}"
    assert message_high == (
        "1 validation error detected: Value '1001' at 'maxResults' failed to satisfy "
        "constraint: Member must have value less than or equal to 1000"
    ), f"unexpected maxResults=1001 message: {message_high!r}"

    code_low, message_low = _error(lambda: raw.list_sessions(maxResults=0))
    assert code_low == "ValidationException", f"expected ValidationException, got {code_low!r}"
    assert message_low == (
        "1 validation error detected: Value '0' at 'maxResults' failed to satisfy "
        "constraint: Member must have value greater than or equal to 1"
    ), f"unexpected maxResults=0 message: {message_low!r}"

    # positive control: the documented upper boundary itself is accepted (not
    # reinterpreted/clamped into an error), proving the rejections above are a real
    # range check and not an unconditional rejection of the parameter.
    resp = client.list_sessions(maxResults=1000)
    assert "sessionSummaries" in resp, f"expected sessionSummaries in response, got {resp!r}"


def _error(fn) -> tuple[str, str]:
    """The (code, message) of the ClientError ``fn`` raises; a success is an AssertionError."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError("expected a ValidationException, the call succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
