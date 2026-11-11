"""get-graph-invalid-identifier-pattern-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-graph-invalid-identifier-pattern-rejected"
GROUP = "error-semantics"
SERVICES = ["neptune-graph"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A malformed graphIdentifier is rejected with ValidationException, distinct from a well-formed-but-missing one."""
    ng = ctx.client("neptune-graph")

    # Control: the same client/account/region genuinely works -- so the rejections below are
    # decisions about the identifier, not a broken endpoint that fails every call.
    live = ng.list_graphs()
    assert "graphs" in live, f"ListGraphs missing 'graphs' key: {live!r}"

    # graphIdentifier must match ^g-[a-z0-9]{10}$ -- this violates the pattern entirely.
    code, msg = _error(lambda: ng.get_graph(graphIdentifier="not-a-valid-id"))
    assert code == "ValidationException", (
        f"GetGraph on a malformed graphIdentifier must be ValidationException, got {code!r}"
    )
    expected = (
        "1 validation error detected: Value 'not-a-valid-id' at 'graphIdentifier' failed to satisfy "
        "constraint: Member must satisfy regular expression pattern: g-[a-z0-9]{10}"
    )
    assert msg == expected, f"expected message {expected!r}, got {msg!r}"

    # A syntactically valid identifier that simply does not exist gets a different, specific
    # error -- proving the ValidationException above is pattern-driven, not a generic catch-all.
    code2, msg2 = _error(lambda: ng.get_graph(graphIdentifier="g-0000000000"))
    assert code2 == "ResourceNotFoundException", (
        f"GetGraph on a well-formed but never-minted graphIdentifier must be "
        f"ResourceNotFoundException, got {code2!r}"
    )
    expected2 = f"No graph found for customer [{ctx.account}] with graph id [g-0000000000]"
    assert msg2 == expected2, f"expected message {expected2!r}, got {msg2!r}"
    assert code != code2, (
        f"GetGraph returned {code!r} for both a malformed identifier and a missing graph; "
        f"pattern validation and resource lookup are not distinct stages"
    )


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
