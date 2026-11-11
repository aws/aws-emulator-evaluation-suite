"""delete-identities-too-many-requests-limit."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-identities-too-many-requests-limit"
GROUP = 'overly-permissive'
SERVICES = ['cognito-identity']

def _error(fn):
    """Call fn(); return its botocore (Code, Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteIdentities rejects 61 IdentityIdsToDelete with ValidationException and the exact
    length-constraint message, and accepts exactly 60, the documented maximum per call."""
    ev = ctx.client("cognito-identity")

    oversized = [f"{ctx.region}:{uuid.uuid4()}" for _ in range(61)]
    code, message = _error(lambda: ev.delete_identities(IdentityIdsToDelete=oversized))
    assert code == "ValidationException", (
        f"expected ValidationException for a 61-item DeleteIdentities batch, got {code}"
    )
    expected = (
        f"1 validation error detected: Value '[{', '.join(oversized)}]' at 'identityIdsToDelete' "
        "failed to satisfy constraint: Member must have length less than or equal to 60"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Boundary companion / positive control: exactly 60 items (still none of them real) must be
    # ACCEPTED — this is what separates "rejects a 61-item batch" from "rejects every batch".
    boundary = [f"{ctx.region}:{uuid.uuid4()}" for _ in range(60)]
    resp = ev.delete_identities(IdentityIdsToDelete=boundary)
    assert "UnprocessedIdentityIds" in resp, (
        f"expected a 60-item (at-limit) DeleteIdentities batch to be accepted, got response {resp}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
