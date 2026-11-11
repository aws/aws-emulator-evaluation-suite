"""domain-lifecycle-create-active-delete."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "domain-lifecycle-create-active-delete"
GROUP = "state-machine"
SERVICES = ["codeartifact"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDomain transitions a domain to ACTIVE and describable; DeleteDomain removes it
    so DescribeDomain subsequently 404s, a mutating call on the dead domain also 404s, and
    the freed name is reusable."""
    ca = ctx.client("codeartifact")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-behav-dom-")

    created = ca.create_domain(domain=name, tags=[{"key": "sim2real", "value": CHECK}])["domain"]
    ctx.on_cleanup(lambda: _teardown(lambda: ca.delete_domain(domain=name)))
    assert created["name"] == name, f"expected created domain name {name!r}, got {created['name']!r}"
    assert created["status"] == "Active", f"expected created domain status Active, got {created['status']!r}"

    described = ca.describe_domain(domain=name)["domain"]
    assert described["status"] == "Active", f"expected described domain status Active, got {described['status']!r}"
    assert described["arn"] == created["arn"], (
        f"expected DescribeDomain arn {created['arn']!r} to match CreateDomain arn, got {described['arn']!r}"
    )

    ca.delete_domain(domain=name)

    gone = _error(lambda: ca.describe_domain(domain=name))
    expected_gone = (
        "ResourceNotFoundException",
        f"Domain not found. Domain '{name}' owned by account '{account_id}' does not exist.",
    )
    assert gone == expected_gone, (
        f"expected DescribeDomain on a deleted domain to raise {expected_gone!r}, got {gone!r}"
    )

    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "codeartifact:DescribeDomain",
            "Resource": created["arn"],
        }],
    }
    mutate = _error(
        lambda: ca.put_domain_permissions_policy(domain=name, policyDocument=json.dumps(policy_doc))
    )
    expected_mutate = expected_gone
    assert mutate == expected_mutate, (
        f"expected PutDomainPermissionsPolicy on a deleted domain to raise {expected_mutate!r}, "
        f"got {mutate!r}"
    )

    recreated = _create_when_name_freed(ca, name)
    assert recreated["name"] == name, f"expected the freed domain name {name!r} to be reusable, got {recreated['name']!r}"
    assert recreated["status"] == "Active", (
        f"expected the recreated domain status to be Active, got {recreated['status']!r}"
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


def _create_when_name_freed(ca, name: str, timeout_s: float = 60.0) -> dict:
    """CreateDomain on a just-deleted name, retrying while the name still reads as taken. RAISES
    on timeout with the last refusal."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return ca.create_domain(domain=name, tags=[{"key": "sim2real", "value": CHECK}])["domain"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ConflictException" or time.monotonic() >= deadline:
                raise AssertionError(
                    f"the deleted domain name {name!r} was not reusable within {timeout_s}s: {exc}"
                ) from exc
            time.sleep(3)


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
