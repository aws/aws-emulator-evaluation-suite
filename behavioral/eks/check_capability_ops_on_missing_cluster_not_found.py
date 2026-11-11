"""capability-ops-on-missing-cluster-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _error_code(fn):
    """Call fn; return the botocore error code, or None if it succeeded."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    return None

CHECK = "capability-ops-on-missing-cluster-not-found"
GROUP = 'error-semantics'
SERVICES = ['eks']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Capability read/update/delete on a nonexistent cluster report not-found."""
    c = ctx.client("eks")
    if not hasattr(c, "describe_capability"):
        raise AssertionError("eks capability APIs not present in this botocore version")

    cluster = ctx.unique_name("sim2real-behav-no-cluster-")
    cap = ctx.unique_name("sim2real-behav-cap-")
    observed = {
        "ListCapabilities": _error_code(lambda: c.list_capabilities(clusterName=cluster)),
        "DescribeCapability": _error_code(
            lambda: c.describe_capability(clusterName=cluster, capabilityName=cap)
        ),
        "UpdateCapability": _error_code(
            lambda: c.update_capability(clusterName=cluster, capabilityName=cap)
        ),
        "DeleteCapability": _error_code(
            lambda: c.delete_capability(clusterName=cluster, capabilityName=cap)
        ),
    }
    mismatches = {op: code for op, code in observed.items() if code != "ResourceNotFoundException"}
    assert not mismatches, f"expected ResourceNotFoundException everywhere, got {mismatches}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
