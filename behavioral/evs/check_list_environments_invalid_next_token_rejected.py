"""list-environments-invalid-next-token-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-environments-invalid-next-token-rejected"
GROUP = "errors"
SERVICES = ["evs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListEnvironments rejects a nextToken it never issued with ValidationException and its
    exact message, while the same call without a token succeeds."""
    evs = ctx.client("evs")

    control = evs.list_environments()
    assert "environmentSummaries" in control, (
        f"positive control failed: list_environments() with no nextToken did "
        f"not return environmentSummaries: {control!r}"
    )

    code, message = _error(
        lambda: evs.list_environments(nextToken="sim2real-not-a-real-token")
    )
    assert code == "ValidationException", (
        f"expected ValidationException for a malformed nextToken, got {code!r}"
    )
    assert message == (
        "The provided nextToken is malformed or has expired. "
        "Please retry with a valid token or start a new list operation."
    ), f"unexpected message {message!r}"


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
