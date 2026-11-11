"""batch-get-fleets-invalid-arn-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-get-fleets-invalid-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["codebuild"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """BatchGetFleets on a malformed fleet identifier must reject, not silently absorb it."""
    codebuild = ctx.client("codebuild")

    # Fleet names/ARNs must match `[A-Za-z0-9][A-Za-z0-9\-_]{1,127}` (see CreateFleet's `name`
    # pattern); this string violates that pattern (spaces, "!") and is not a well-formed ARN
    # either, so it must be rejected outright rather than parked in fleetsNotFound.
    malformed = "not a valid fleet name!!"
    code, message = _error(lambda: codebuild.batch_get_fleets(names=[malformed]))
    assert code == "InvalidInputException", f"expected InvalidInputException, got {code!r}"
    expected_message = (
        "Invalid characters in fleet name. Only alphanumeric characters, dash, and underscore are supported"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Positive control: a syntactically well-formed but nonexistent name is accepted, not
    # raised as an error -- confirming the negative above is about format, not existence.
    # Measured on real AWS: a bare (non-ARN) name that matches no fleet is silently dropped
    # from BOTH lists rather than being surfaced in fleetsNotFound.
    wellformed_missing = ctx.unique_name("sim2real-cb-fleet-")
    response = codebuild.batch_get_fleets(names=[wellformed_missing])
    # Positive-control invariant: whatever bookkeeping AWS does for a well-formed-but-
    # nonexistent name, it must NEVER fabricate a Fleet object for it.
    assert response["fleets"] == [], f"expected no fleets, got {response['fleets']!r}"
    assert response["fleetsNotFound"] == [], (
        f"expected fleetsNotFound empty, got {response['fleetsNotFound']!r}"
    )


def _error(fn) -> tuple[str, str]:
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(
        f"expected the call to be rejected, but it succeeded and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
