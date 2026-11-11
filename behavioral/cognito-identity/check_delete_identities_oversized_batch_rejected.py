"""delete-identities-oversized-batch-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-identities-oversized-batch-rejected"
GROUP = "error-semantics"
SERVICES = ["cognito-identity"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteIdentities with 61 ids fails with ValidationException and its exact message, while a batch of
    exactly 60 never-issued ids is accepted with no unprocessed ids.
    """
    ci = ctx.client("cognito-identity")
    region = ctx.region

    too_many = [f"{region}:{uuid.uuid4()}" for _ in range(61)]
    code, message = _error(lambda: ci.delete_identities(IdentityIdsToDelete=too_many))
    # Real AWS rejects an oversized batch with ValidationException (shape-level
    # max-items constraint on IdentityIdsToDelete), not InvalidParameterException.
    assert code == "ValidationException", (
        f"expected ValidationException for a 61-id batch (documented limit is 60), got {code!r}"
    )
    expected = (
        f"1 validation error detected: Value '[{', '.join(too_many)}]' at 'identityIdsToDelete' "
        "failed to satisfy constraint: Member must have length less than or equal to 60"
    )
    assert message == expected, f"expected refusal message {expected!r}, got {message!r}"

    # Positive control at the exact boundary: 60 ids (the documented max) is accepted,
    # and since none of them were ever issued, none comes back unprocessed.
    ok_batch = [f"{region}:{uuid.uuid4()}" for _ in range(60)]
    resp = ci.delete_identities(IdentityIdsToDelete=ok_batch)
    unprocessed = resp.get("UnprocessedIdentityIds", [])
    assert unprocessed == [], (
        f"expected a 60-id (at-limit) batch of never-issued ids to be fully accepted "
        f"with none unprocessed, got {unprocessed!r}"
    )


def _error(fn):
    """Call fn(); return its botocore (Error.Code, Error.Message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
