"""list-deployments-filter-by-invalid-status-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-deployments-filter-by-invalid-status-rejected"
GROUP = "overly-permissive"
SERVICES = ["launch-wizard"]


def _client_error(fn):
    """Call fn(); return the (code, message) of its ClientError. An unexpected success raises, so
    a target that accepts what AWS refuses fails loudly instead of reading as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListDeployments rejects a DEPLOYMENT_STATUS filter value with characters outside the modeled pattern
    with ValidationException and its exact message; the same filter with a real status returns no deployments."""
    lw = ctx.client("launch-wizard")

    code, message = _client_error(
        lambda: lw.list_deployments(
            filters=[{"name": "DEPLOYMENT_STATUS", "values": ["not a valid status!!"]}],
            maxResults=10,
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == (
        "1 validation error detected: Value at 'filters.1.member.values' failed to satisfy "
        "constraint: Member must satisfy constraint: [Member must have length less than or equal "
        "to 100, Member must have length greater than or equal to 1, Member must satisfy regular "
        "expression pattern: .*(^(([A-Za-z])+([0-9A-Za-z\\-\\_])+)$).*]"
    ), f"got message={message!r}"

    # contrast: an unknown value that still satisfies the character pattern is accepted,
    # not rejected -- the service doesn't enum-validate filter values, just pattern-checks them,
    # and since no real deployment carries this invented status it matches nothing
    resp = lw.list_deployments(
        filters=[{"name": "DEPLOYMENT_STATUS", "values": ["NOT_A_REAL_STATUS"]}], maxResults=10
    )
    assert resp["deployments"] == [], (
        f"expected no deployments to match invented status NOT_A_REAL_STATUS, got {resp['deployments']!r}"
    )

    # positive control: the same filter shape with a real enum value is accepted
    lw.list_deployments(filters=[{"name": "DEPLOYMENT_STATUS", "values": ["COMPLETED"]}], maxResults=10)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
