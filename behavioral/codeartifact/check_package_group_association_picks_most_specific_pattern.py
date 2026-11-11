"""package-group-association-picks-most-specific-pattern."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "package-group-association-picks-most-specific-pattern"
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


def _associated(ca, domain, package, namespace=None, fmt="generic"):
    kw = dict(domain=domain, format=fmt, package=package)
    if namespace is not None:
        kw["namespace"] = namespace
    return ca.get_associated_package_group(**kw)


def _await_association(ca, domain, package, namespace, pattern, deadline=90.0):
    """Poll GetAssociatedPackageGroup until it reports pattern, then return the last response.

    New groups reach the association index asynchronously; an immediate lookup can still return
    the previous best match.
    """
    end = time.time() + deadline
    while True:
        got = _associated(ca, domain, package, namespace)
        if got["packageGroup"]["pattern"] == pattern or time.time() >= end:
            return got
        time.sleep(2)


@tags("axis:happy-path", "cap:c7", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetAssociatedPackageGroup resolves a package to the MOST SPECIFIC matching pattern as nested
    patterns are added, while packages just outside each pattern resolve to its ancestor.
    """
    ca = ctx.client("codeartifact")
    domain = ctx.unique_name("sim2real-behav-ca-dom-")
    package = "sim2real-thing"
    namespace = "sim2real-scope"

    ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_domain(ca, domain))

    root = _associated(ca, domain, package, namespace)
    assert root["packageGroup"]["pattern"] == "/*", (
        f"in a fresh domain {package!r} resolves to {root['packageGroup']['pattern']!r}, expected "
        f"the root group '/*'"
    )
    assert root["associationType"] == "STRONG", (
        f"the root association type is {root['associationType']!r}, expected STRONG"
    )

    steps = [
        "/generic/*",
        "/generic/%s/*" % namespace,
        "/generic/%s/%s$" % (namespace, package),
    ]
    for pattern in steps:
        created = ca.create_package_group(
            domain=domain, packageGroup=pattern,
            tags=[{"key": "sim2real", "value": CHECK}],
        )
        ctx.on_cleanup(lambda p=pattern: ca.delete_package_group(domain=domain, packageGroup=p))
        assert created["packageGroup"]["pattern"] == pattern, (
            f"CreatePackageGroup echoed pattern {created['packageGroup']['pattern']!r}, "
            f"expected {pattern!r}"
        )
        now = _await_association(ca, domain, package, namespace, pattern)
        assert now["packageGroup"]["pattern"] == pattern, (
            f"after adding {pattern!r} the package resolves to "
            f"{now['packageGroup']['pattern']!r}; the most specific match must win"
        )

    # Each sibling just outside a pattern falls back to that pattern's own ancestor.
    other_package = _await_association(ca, domain, "sim2real-other", namespace,
                                       "/generic/%s/*" % namespace)
    assert other_package["packageGroup"]["pattern"] == "/generic/%s/*" % namespace, (
        f"a different package in the same namespace resolves to "
        f"{other_package['packageGroup']['pattern']!r}, expected the namespace group"
    )
    other_namespace = _await_association(ca, domain, package, "sim2real-elsewhere",
                                         "/generic/*")
    assert other_namespace["packageGroup"]["pattern"] == "/generic/*", (
        f"the same package in a different namespace resolves to "
        f"{other_namespace['packageGroup']['pattern']!r}, expected the format group '/generic/*'"
    )
    other_format = _associated(ca, domain, "lodash", None, fmt="npm")
    assert other_format["packageGroup"]["pattern"] == "/*", (
        f"an npm package resolves to {other_format['packageGroup']['pattern']!r}, expected the "
        f"root group '/*' — none of the generic patterns may claim it"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
