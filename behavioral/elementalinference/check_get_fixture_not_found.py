"""get-fixture-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-fixture-not-found"
GROUP = "errors"
SERVICES = ["elementalinference"]


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING an id real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected GetFixture to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetFixture on an unresolvable fixtureId, numeric or not, fails with ValidationException and the exact
    message naming that id, never ResourceNotFoundException."""
    ei = ctx.client("elementalinference")
    for bogus_id in ("sim2real-behav-does-not-exist-fixture-id", "90210675312"):
        err = _error(lambda bogus_id=bogus_id: ei.get_fixture(fixtureId=bogus_id))
        assert err.get("Code") == "ValidationException", err
        assert err.get("Message") == (
            f"Can't find fixture {bogus_id}. Use a different fixtureId and try again."
        ), err


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

