"""package-group-origin-configuration-inherited-by-subgroups."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "package-group-origin-configuration-inherited-by-subgroups"
GROUP = "server-side"
SERVICES = ["codeartifact"]


@tags("axis:happy-path", "cap:c7", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A sub package group with no setting of its own inherits its parent's EXTERNAL_UPSTREAM=BLOCK:
    `mode` stays INHERIT, `effectiveMode` is BLOCK, `inheritedFrom` names the parent's pattern,
    and ListSubPackageGroups on the parent lists the child.
    """
    ca = ctx.client("codeartifact")
    domain = ctx.unique_name("sim2real-capkggrp-")
    ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: ca.delete_domain(domain=domain))

    parent_pattern = "/npm/*"
    ns = ctx.unique_name("scope").replace("-", "")
    child_pattern = f"/npm/{ns}/*"

    ca.create_package_group(domain=domain, packageGroup=parent_pattern,
                             tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: ca.delete_package_group(domain=domain, packageGroup=parent_pattern))
    ca.create_package_group(domain=domain, packageGroup=child_pattern,
                             tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: ca.delete_package_group(domain=domain, packageGroup=child_pattern))

    ca.update_package_group_origin_configuration(
        domain=domain,
        packageGroup=parent_pattern,
        restrictions={"EXTERNAL_UPSTREAM": "BLOCK"},
    )

    sub_groups = _poll_for_sub_group(ca, domain, parent_pattern, child_pattern, timeout_s=60.0)
    assert child_pattern in sub_groups, (
        f"ListSubPackageGroups on the parent {parent_pattern!r} returned {sub_groups!r}, "
        f"expected it to include the child {child_pattern!r}"
    )

    restriction = _poll_for_effective_mode(
        ca, domain, child_pattern, expected_mode="BLOCK", timeout_s=60.0
    )
    assert restriction["mode"] == "INHERIT", (
        f"the child's own EXTERNAL_UPSTREAM mode is {restriction['mode']!r}; it was never set "
        f"explicitly so it must stay INHERIT"
    )
    assert restriction["effectiveMode"] == "BLOCK", (
        f"the child's effectiveMode is {restriction['effectiveMode']!r}, expected BLOCK inherited "
        f"from the parent's own explicit setting"
    )
    assert restriction["inheritedFrom"]["pattern"] == parent_pattern, (
        f"the child says it inherited from {restriction['inheritedFrom']!r}, expected the parent "
        f"{parent_pattern!r}"
    )


def _poll_for_sub_group(ca, domain, parent_pattern, child_pattern, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    patterns: list = []
    while time.monotonic() < deadline:
        sub_groups = ca.list_sub_package_groups(domain=domain, packageGroup=parent_pattern)[
            "packageGroups"
        ]
        patterns = [g["pattern"] for g in sub_groups]
        if child_pattern in patterns:
            return patterns
        time.sleep(interval_s)
    raise AssertionError(f"child pattern never appeared under parent: {patterns}")


def _poll_for_effective_mode(ca, domain, child_pattern, expected_mode, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    restriction = None
    while time.monotonic() < deadline:
        child_desc = ca.describe_package_group(domain=domain, packageGroup=child_pattern)[
            "packageGroup"
        ]
        restriction = child_desc["originConfiguration"]["restrictions"]["EXTERNAL_UPSTREAM"]
        if restriction.get("effectiveMode") == expected_mode:
            return restriction
        time.sleep(interval_s)
    raise AssertionError(f"effectiveMode never became {expected_mode}: {restriction}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

