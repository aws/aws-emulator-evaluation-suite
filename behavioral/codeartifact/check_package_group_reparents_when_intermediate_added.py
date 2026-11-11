"""package-group-reparents-when-intermediate-added."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "package-group-reparents-when-intermediate-added"
GROUP = 'package-groups'
SERVICES = ['codeartifact']


def _delete_domain(ca, domain, deadline=90.0):
    end = time.time() + deadline
    while True:
        try:
            ca.delete_domain(domain=domain)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ConflictException" or time.time() >= end:
                raise
            time.sleep(3)


def _await_parent(ca, domain, pattern, want_parent, deadline=90.0):
    """Poll DescribePackageGroup until pattern's parent is want_parent, then return the group.

    Re-parenting propagates asynchronously: measured, an immediate describe after creating the
    intermediate group still names the old parent. Returns the last answer either way so the
    caller's assert can quote what it actually saw.
    """
    end = time.time() + deadline
    while True:
        got = ca.describe_package_group(domain=domain, packageGroup=pattern)["packageGroup"]
        if got.get("parent", {}).get("pattern") == want_parent or time.time() >= end:
            return got
        time.sleep(2)


def _sub_patterns(ca, domain, parent):
    out = []
    for page in ca.get_paginator("list_sub_package_groups").paginate(
            domain=domain, packageGroup=parent):
        out.extend(g["pattern"] for g in page["packageGroups"])
    return sorted(out)


def _all_patterns(ca, domain):
    out = []
    for page in ca.get_paginator("list_package_groups").paginate(domain=domain):
        out.extend(g["pattern"] for g in page["packageGroups"])
    return sorted(out)


@tags("axis:happy-path", "cap:c7", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Creating an intermediate package group moves an existing leaf from the root group to the new
    group: its parent pattern and ARN change and the sub-group lists of both groups follow."""
    ca = ctx.client("codeartifact")
    domain = ctx.unique_name("sim2real-behav-ca-dom-")
    leaf = "/generic/sim2real-scope/*"
    intermediate = "/generic/*"

    ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_domain(ca, domain))

    created = ca.create_package_group(
        domain=domain, packageGroup=leaf, tags=[{"key": "sim2real", "value": CHECK}]
    )
    ctx.on_cleanup(lambda: ca.delete_package_group(domain=domain, packageGroup=leaf))
    assert created["packageGroup"]["parent"]["pattern"] == "/*", (
        f"the leaf group's parent at create time is "
        f"{created['packageGroup']['parent']['pattern']!r}; with nothing in between it must be "
        f"the root '/*'"
    )
    assert _sub_patterns(ca, domain, "/*") == [leaf], (
        f"the root's direct sub-groups are {_sub_patterns(ca, domain, '/*')!r}, expected [{leaf!r}]"
    )

    ca.create_package_group(
        domain=domain, packageGroup=intermediate, tags=[{"key": "sim2real", "value": CHECK}]
    )
    ctx.on_cleanup(lambda: ca.delete_package_group(domain=domain, packageGroup=intermediate))

    moved = _await_parent(ca, domain, leaf, intermediate)
    assert moved["parent"]["pattern"] == intermediate, (
        f"after adding {intermediate!r} the leaf's parent is {moved['parent']['pattern']!r}; "
        f"creating an intermediate pattern must re-parent the groups already beneath it"
    )
    assert moved["parent"]["arn"].endswith("/generic/%2a"), (
        f"the re-parented arn is {moved['parent']['arn']!r}; the pattern's '*' must be "
        f"percent-encoded in a package-group arn"
    )

    assert _sub_patterns(ca, domain, "/*") == [intermediate], (
        f"the root's direct sub-groups are now {_sub_patterns(ca, domain, '/*')!r}; the leaf must "
        f"have moved out and only the intermediate remain"
    )
    assert _sub_patterns(ca, domain, intermediate) == [leaf], (
        f"the intermediate's direct sub-groups are "
        f"{_sub_patterns(ca, domain, intermediate)!r}, expected [{leaf!r}]"
    )
    assert _all_patterns(ca, domain) == sorted(["/*", intermediate, leaf]), (
        f"the domain holds groups {_all_patterns(ca, domain)!r}, expected exactly the root, the "
        f"intermediate and the leaf"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
