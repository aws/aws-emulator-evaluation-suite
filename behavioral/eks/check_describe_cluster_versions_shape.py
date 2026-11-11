"""describe-cluster-versions-shape."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "describe-cluster-versions-shape"
GROUP = 'metadata'
SERVICES = ['eks']

def _rejects_with(fn, expected_code):
    """Call fn; raise unless it fails with exactly expected_code."""
    try:
        fn()
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        assert code == expected_code, f"expected {expected_code!r}, got {code!r}"
        return
    raise AssertionError(f"expected {expected_code!r} but the call succeeded")

@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeClusterVersions returns the Kubernetes version catalog with support-lifecycle status and dates per version, and rejects a malformed filter."""
    c = ctx.client("eks")
    resp = c.describe_cluster_versions()
    versions = resp.get("clusterVersions", [])
    assert versions, "expected a non-empty cluster version catalog"

    # Empirically, real EKS reports these as SCREAMING_SNAKE_CASE.
    known_status = {
        "UNSUPPORTED",
        "STANDARD_SUPPORT",
        "EXTENDED_SUPPORT",
    }
    defaults = 0
    for entry in versions:
        assert entry["clusterVersion"].startswith("1."), entry
        assert entry["clusterType"], entry
        status = entry["versionStatus"]
        assert status in known_status, f"unexpected version status {status!r}: {entry}"
        # The legacy `status` field must agree with `versionStatus`.
        assert entry.get("status") == status, entry
        if entry.get("defaultVersion"):
            defaults += 1

    assert defaults >= 1, "no Kubernetes version flagged as the default"

    # The happy path above is the positive control: the catalog read genuinely
    # works, so a rejection below cannot be explained by "nothing works here".
    members = c.meta.service_model.operation_model("DescribeClusterVersions").input_shape.members
    if "clusterVersions" in members:
        _rejects_with(
            lambda: c.describe_cluster_versions(clusterVersions=["not-a-version"]),
            "InvalidParameterException",
        )
    if "versionStatus" in members:
        _rejects_with(
            lambda: c.describe_cluster_versions(versionStatus="NOT_A_STATUS"),
            "InvalidParameterException",
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
