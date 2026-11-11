"""list-deployments-filter-by-workload-name-no-match-returns-empty."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-deployments-filter-by-workload-name-no-match-returns-empty"
GROUP = "state"
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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListDeployments returns an empty list for a WORKLOAD_NAME filter that matches nothing, and rejects a
    filter value outside the modeled character pattern with ValidationException and its exact message."""
    lw = ctx.client("launch-wizard")
    bogus_workload = ctx.unique_name("Sim2RealNoSuchWorkload").replace("-", "")

    # negative (always-invalid-input, no restore leg by construction): a filter value that
    # violates the modeled character pattern is rejected outright, before any resource lookup
    code, message = _client_error(
        lambda: lw.list_deployments(
            filters=[{"name": "WORKLOAD_NAME", "values": ["not a valid name!!"]}],
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

    # positive control: the identical filter shape with a pattern-legal value is accepted,
    # not rejected -- and since no deployment carries this invented name, it matches nothing
    # and returns an empty result rather than ResourceNotFoundException
    resp = lw.list_deployments(
        filters=[{"name": "WORKLOAD_NAME", "values": [bogus_workload]}], maxResults=10
    )
    assert resp["deployments"] == [], (
        f"expected no deployments to match invented workload name {bogus_workload!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
