"""describe-addon-versions-filters."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "describe-addon-versions-filters"
GROUP = 'metadata'
SERVICES = ['eks']

@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeAddonVersions filters are applied server-side: a kubernetesVersion filter only returns versions compatible with it, and an owner filter only returns that owner's add-ons."""
    c = ctx.client("eks")
    # 1. kubernetesVersion filter: every returned version must actually declare
    #    compatibility with the requested Kubernetes version.
    target_k8s = "1.31"
    resp = c.describe_addon_versions(kubernetesVersion=target_k8s)
    addons = resp.get("addons", [])
    assert addons, f"expected add-ons compatible with k8s {target_k8s}"

    checked = 0
    for addon in addons:
        for info in addon["addonVersions"]:
            compat = {c["clusterVersion"] for c in info.get("compatibilities", [])}
            assert target_k8s in compat, (
                f"{addon['addonName']} {info['addonVersion']} returned for "
                f"k8s {target_k8s} but declares {sorted(compat)}"
            )
            checked += 1
    assert checked > 0, resp

    # 2. owner filter must not leak third-party/marketplace add-ons.
    aws_owned = c.describe_addon_versions(owners=["aws"]).get("addons", [])
    assert aws_owned, "expected at least one aws-owned add-on"
    owners = {a["owner"] for a in aws_owned}
    assert owners == {"aws"}, f"owners=['aws'] leaked other owners: {owners}"

    # The unfiltered catalogue is strictly larger than the aws-only slice,
    # which proves the filter actually narrowed the result set.
    all_names = {a["addonName"] for a in c.describe_addon_versions()["addons"]}
    aws_names = {a["addonName"] for a in aws_owned}
    assert aws_names < all_names, (
        f"owner filter did not narrow the catalogue: {len(aws_names)} vs {len(all_names)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
