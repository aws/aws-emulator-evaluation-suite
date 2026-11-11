"""op-list-clusters-rejects-invalid-state-filter."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-list-clusters-rejects-invalid-state-filter"
GROUP = 'overly-permissive'
SERVICES = ['emr']

def _error(fn):
    """Invoke *fn*, asserting it is rejected; return the (code, message) pair."""
    try:
        fn()
    except Exception as exc:
        err = (getattr(exc, "response", {}) or {}).get("Error", {})
        return err.get("Code", type(exc).__name__), err.get("Message", "")
    raise AssertionError("expected the operation to be rejected, but it succeeded")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """OVERLY-PERMISSIVE: an unknown ClusterStates value must be rejected rather
    than silently ignored (which would widen the result set)."""
    emr = ctx.client("emr")
    code, message = _error(lambda: emr.list_clusters(ClusterStates=["NOPE"]))
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}"
    assert message == "Cluster states [NOPE] are not valid.", (
        f"expected AWS's exact invalid-state message, got {message!r}"
    )

    # Positive control: an identical call shape with a valid ClusterState enum value
    # succeeds, proving the rejection above is specific to the invalid value rather than
    # ListClusters (or its ClusterStates filter) being broken or refused outright.
    resp = emr.list_clusters(ClusterStates=["RUNNING"])
    assert "Clusters" in resp, f"expected a well-formed ListClusters response, got {resp!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
