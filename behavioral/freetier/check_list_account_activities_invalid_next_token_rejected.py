"""list-account-activities-invalid-next-token-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-account-activities-invalid-next-token-rejected"
GROUP = "error-semantics"
SERVICES = ["freetier"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A nextToken that was never issued by the service is rejected with ValidationException."""
    freetier = ctx.client("freetier")

    control = freetier.list_account_activities()
    assert isinstance(control["activities"], list), control

    error = _client_error(
        lambda: freetier.list_account_activities(nextToken="not-a-real-pagination-token")
    )
    assert error["Code"] == "ValidationException", error
    assert error["Message"] == "Invalid nextToken", error["Message"]


def _client_error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected rejection but call succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
