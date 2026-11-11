"""list-relationships-validation-precedes-access-denied."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-relationships-validation-precedes-access-denied"
GROUP = "error-semantics"
SERVICES = ["partnercentral-channel"]

CATALOG = "Sandbox"
BENEFIT_DENIED = (
    "This action requires an active AWS Partner benefit. Register as an AWS Partner "
    "if you haven't already, or contact AWS Partner Central Support."
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListRelationships rejects maxResults 500 with ValidationException (exact message and fieldList),
    while a valid maxResults for the same catalog gets the exact entitlement AccessDeniedException:
    validation runs before authorization."""
    client = ctx.client("partnercentral-channel")

    def _attempt_out_of_range():
        return client.list_relationships(catalog=CATALOG, maxResults=500)

    rejected = _error(_attempt_out_of_range)
    code = rejected["Error"]["Code"]
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    assert rejected["Error"].get("Message") == "1 validation error detected.", rejected
    assert rejected.get("fieldList") == [
        {
            "name": "maxResults",
            "code": "INVALID_VALUE",
            "message": "Value at 'maxResults' failed to satisfy constraint: "
            "Member must have value less than or equal to 100",
        }
    ], f"fieldList={rejected.get('fieldList')!r}"

    def _attempt_in_range():
        return client.list_relationships(catalog=CATALOG, maxResults=50)

    denied = _error(_attempt_in_range)
    code2 = denied["Error"]["Code"]
    assert code2 == "AccessDeniedException", f"expected AccessDeniedException, got {code2}"
    assert denied["Error"].get("Message") == BENEFIT_DENIED, denied


def _error(fn):
    """Call fn(); return its botocore response dict (Code/Message under "Error", modeled
    error members such as fieldList at the top level). An unexpected SUCCESS raises, so a
    target that accepts input real AWS refuses cannot pass as an error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
