"""list-controls-implementation-identifier-pattern-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-controls-implementation-identifier-pattern-rejected"
GROUP = "error-semantics"
SERVICES = ["controlcatalog"]

_INVALID_IDENTIFIER = (
    "ValidationException",
    "1 validation error detected: Value at 'filter.implementations.identifiers' failed to "
    "satisfy constraint: Member must satisfy constraint: [Member must have length less than "
    "or equal to 256, Member must have length greater than or equal to 1, Member must satisfy "
    "regular expression pattern: [a-zA-Z0-9_\\.-]+]",
)


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def expect_error(fn, code, message):
    got_code, got_message = _error(fn)
    assert got_code == code, f"expected {code}, got {got_code}: {got_message!r}"
    assert got_message == message, f"expected message {message!r}, got {got_message!r}"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A single-element Filter.Implementations.Identifiers value with a character outside
    ^[a-zA-Z0-9_.-]+$ is rejected with ValidationException; a well-formed but unmatched
    identifier is accepted and scopes ListControls to an empty result."""
    cc = ctx.client("controlcatalog")

    expect_error(
        lambda: cc.list_controls(
            MaxResults=10,
            Filter={"Implementations": {"Identifiers": ["bad identifier!"]}},
        ),
        *_INVALID_IDENTIFIER,
    )

    unmatched_identifier = ctx.unique_name("sim2real-cc-unmatched-id-")
    scoped = cc.list_controls(
        MaxResults=10,
        Filter={"Implementations": {"Identifiers": [unmatched_identifier]}},
    )
    assert scoped["Controls"] == [], (
        f"a well-formed, unmatched Identifiers filter should scope to no controls, "
        f"got {scoped['Controls']!r}"
    )
    assert "NextToken" not in scoped, (
        f"an empty result should carry no NextToken, got {scoped.get('NextToken')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
