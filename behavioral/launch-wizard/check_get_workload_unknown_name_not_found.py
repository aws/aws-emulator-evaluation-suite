"""get-workload-unknown-name-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-workload-unknown-name-not-found"
GROUP = "error-semantics"
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


@tags("axis:rejection", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetWorkload for a well-formed but nonexistent workload name raises
    ResourceNotFoundException, while a real workload name resolves successfully
    through the identical operation in the same call sequence."""
    lw = ctx.client("launch-wizard")
    bogus_name = "Sim2RealNoSuchWorkloadXyz"

    code, message = _client_error(lambda: lw.get_workload(workloadName=bogus_name))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    assert message == "The specified workload does not exist or insufficient permissions.", (
        f"got message={message!r}"
    )

    # positive control: a real workload name still resolves via the same operation
    workloads = lw.list_workloads(maxResults=1)["workloads"]
    assert workloads, "expected at least one workload in the catalog"
    lw.get_workload(workloadName=workloads[0]["workloadName"])


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
