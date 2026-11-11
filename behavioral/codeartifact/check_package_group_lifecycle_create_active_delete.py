"""package-group-lifecycle-create-active-delete."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "package-group-lifecycle-create-active-delete"
GROUP = "state-machine"
SERVICES = ["codeartifact"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreatePackageGroup creates a resolvable group; DeletePackageGroup removes it so
    DescribePackageGroup returns ResourceNotFoundException."""
    ca = ctx.client("codeartifact")
    domain = ctx.unique_name("sim2real-behav-dom-")
    ns = ctx.unique_name("sim2real-behav-pg-")
    pattern = f"/generic/{ns}/*"

    ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _teardown(lambda: ca.delete_domain(domain=domain)))

    created = ca.create_package_group(domain=domain, packageGroup=pattern)["packageGroup"]
    ctx.on_cleanup(lambda: _teardown(lambda: ca.delete_package_group(domain=domain, packageGroup=pattern)))
    assert created["pattern"] == pattern
    assert created["domainName"] == domain

    described = ca.describe_package_group(domain=domain, packageGroup=pattern)["packageGroup"]
    assert described["arn"] == created["arn"]
    assert described["pattern"] == pattern

    ca.delete_package_group(domain=domain, packageGroup=pattern)

    gone = _error(lambda: ca.describe_package_group(domain=domain, packageGroup=pattern))
    expected = (
        "ResourceNotFoundException",
        f"Package Group not found not found. Package Group '{pattern}' in domain {domain} owned by "
        f"account {ctx.account} does not exist",
    )
    assert gone == expected, (
        f"DescribePackageGroup on a deleted group returned {gone!r}, expected {expected!r}"
    )


# ===== shared helpers =====
def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message", "")
    raise AssertionError(f"the call SUCCEEDED where real AWS refuses it and returned {result!r}")


def _teardown(fn, timeout_s: float = 30.0) -> None:
    """Run a teardown call: done on success or ResourceNotFoundException, retried while
    ConflictException says a dependent is still being released, and raised otherwise."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException" or time.monotonic() >= deadline:
                raise
            time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
