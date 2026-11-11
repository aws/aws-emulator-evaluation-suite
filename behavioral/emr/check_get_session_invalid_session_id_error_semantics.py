"""get-session-invalid-session-id-error-semantics."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-session-invalid-session-id-error-semantics"
GROUP = "error-semantics"
SERVICES = ["emr"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetSession with a malformed SessionId fails with ValidationException and its exact message, never
    InternalServerException, while the unknown cluster alone fails with InvalidRequestException."""
    emr = ctx.client("emr")

    # Positive control: a well-formed (but nonexistent) SessionId on the same
    # well-formed (but nonexistent) ClusterId must clear input validation and
    # fail at lookup instead -- proving ValidationException below is earned by
    # the malformed shape, not by GetSession rejecting every call outright.
    control_code, control_message = _error(
        lambda: emr.get_session(
            ClusterId="j-INVALIDCLUSTERID1",
            SessionId="is-" + ("0" * 13),
        )
    )
    assert control_code == "InvalidRequestException", (
        f"positive control failed: well-formed-but-nonexistent SessionId must reach lookup "
        f"and fail with InvalidRequestException, got CODE={control_code!r}"
    )
    assert control_message == "Cluster id 'j-INVALIDCLUSTERID1' is not valid.", control_message

    code, message = _error(
        lambda: emr.get_session(
            ClusterId="j-INVALIDCLUSTERID1",
            SessionId="not a valid !! session /// id \x01\x02",
        )
    )
    assert code == "ValidationException", f"CODE={code!r}"
    assert message == (
        "sessionId 'j-INVALIDCLUSTERID1/session/not a valid !! session /// id \x01\x02' is not valid."
    ), message
    assert code != "InternalServerException", "malformed input must not surface as a 500-class internal error"


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
