"""list-controls-implementation-filter-identifier-and-type-combine."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-controls-implementation-filter-identifier-and-type-combine"
GROUP = "error-semantics"
SERVICES = ["controlcatalog"]

_TOO_MANY_IDENTIFIERS = (
    "ValidationException",
    "1 validation error detected: Value at 'filter.implementations.identifiers' failed to "
    "satisfy constraint: Member must have length less than or equal to 1",
)


def _raised(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails
    loudly, since an implementation accepting input real AWS refuses is the behavior under test."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded with {result!r}")


def expect_error(fn, code, message):
    got_code, got_message = _raised(fn)
    assert got_code == code, f"expected error code {code!r}, got {got_code!r} ({got_message!r})"
    assert got_message == message, f"expected message {message!r}, got {got_message!r}"


@tags("axis:rejection", "cap:c5", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListControls refuses a Filter.Implementations.Identifiers list with more than one element.
    Pairing a single identifier with its own control's implementation type resolves to that
    control; the same identifier paired with a different, well-formed type resolves to none.
    """
    cc = ctx.client("controlcatalog")

    page = cc.list_controls(MaxResults=100)
    controls = page["Controls"]
    assert controls, "expected ListControls to return at least one control"

    implemented = [c for c in controls if c.get("Implementation", {}).get("Identifier")]
    assert implemented, "expected at least one control with an Implementation.Identifier set"
    target = implemented[0]
    target_type = target["Implementation"]["Type"]
    target_identifier = target["Implementation"]["Identifier"]

    other_type = next(
        (
            c["Implementation"]["Type"]
            for c in controls
            if c.get("Implementation", {}).get("Type") not in (None, target_type)
        ),
        None,
    )
    assert other_type is not None, (
        "expected a second, differently-typed Implementation among the first page of controls"
    )

    other_identifier = next(
        (
            c["Implementation"]["Identifier"]
            for c in implemented
            if c["Implementation"]["Identifier"] != target_identifier
        ),
        target_identifier,
    )

    expect_error(
        lambda: cc.list_controls(
            Filter={"Implementations": {"Identifiers": [target_identifier, other_identifier]}}
        ),
        *_TOO_MANY_IDENTIFIERS,
    )

    matched = cc.list_controls(
        Filter={"Implementations": {"Types": [target_type], "Identifiers": [target_identifier]}}
    )
    matched_arns = [c["Arn"] for c in matched["Controls"]]
    assert matched_arns == [target["Arn"]], (
        f"identifier {target_identifier!r} paired with its own type {target_type!r} returned "
        f"{matched_arns!r}, expected exactly [{target['Arn']!r}]"
    )
    assert "NextToken" not in matched, (
        f"a single-control match still carried a NextToken: {matched.get('NextToken')!r}"
    )

    mismatched = cc.list_controls(
        Filter={"Implementations": {"Types": [other_type], "Identifiers": [target_identifier]}}
    )
    assert mismatched["Controls"] == [], (
        f"identifier {target_identifier!r} paired with the unrelated type {other_type!r} "
        f"returned {mismatched['Controls']!r}, expected no controls"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
