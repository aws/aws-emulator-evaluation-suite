"""domain-unit-hierarchy-ancestors."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "domain-unit-hierarchy-ancestors"
GROUP = "state-machine"
SERVICES = ["datazone"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A domain unit's ancestorDomainUnitIds (returned only by CreateDomainUnit -- neither
    GetDomainUnit nor ListDomainUnitsForParent exposes it) accumulates every ancestor up to the
    root, verified by independently walking the parentDomainUnitId chain via GetDomainUnit."""
    dz = ctx.client("datazone")
    domain = _create_domain(ctx)
    root_id = domain["rootDomainUnitId"]

    child = dz.create_domain_unit(
        domainIdentifier=domain["id"],
        name=ctx.unique_name("sim2real-dz-du-"),
        parentDomainUnitIdentifier=root_id,
    )
    ctx.on_cleanup(_safe(lambda: dz.delete_domain_unit(domainIdentifier=domain["id"], identifier=child["id"])))

    grandchild = dz.create_domain_unit(
        domainIdentifier=domain["id"],
        name=ctx.unique_name("sim2real-dz-du-"),
        parentDomainUnitIdentifier=child["id"],
    )
    ctx.on_cleanup(
        _safe(lambda: dz.delete_domain_unit(domainIdentifier=domain["id"], identifier=grandchild["id"]))
    )

    # independent read: GetDomainUnit is a different operation than CreateDomainUnit
    child_read = dz.get_domain_unit(domainIdentifier=domain["id"], identifier=child["id"])
    assert child_read["parentDomainUnitId"] == root_id, (
        f"expected child's independently-read parent to be root {root_id!r}, got "
        f"{child_read['parentDomainUnitId']!r}"
    )

    grandchild_read = dz.get_domain_unit(domainIdentifier=domain["id"], identifier=grandchild["id"])
    assert grandchild_read["parentDomainUnitId"] == child["id"], (
        f"expected grandchild's independently-read parent to be child {child['id']!r}, got "
        f"{grandchild_read['parentDomainUnitId']!r}"
    )

    # ancestorDomainUnitIds has no independent reader anywhere in the API (neither GetDomainUnit
    # nor ListDomainUnitsForParent returns it), so hold each create-time value to an ancestor
    # chain reconstructed purely from independently-read parentDomainUnitId links, so the
    # expected value is derived independently rather than taken from the create response.
    child_chain = _walk_ancestors(dz, domain["id"], child_read["parentDomainUnitId"], root_id)
    assert set(child["ancestorDomainUnitIds"]) == set(child_chain), (
        f"CreateDomainUnit reported ancestorDomainUnitIds={child['ancestorDomainUnitIds']!r} for "
        f"the child but the independently-walked chain is {child_chain!r}"
    )

    grandchild_chain = _walk_ancestors(dz, domain["id"], grandchild_read["parentDomainUnitId"], root_id)
    assert grandchild_chain == [child["id"], root_id], (
        f"expected the independently-walked ancestor chain to be [child, root] = "
        f"{[child['id'], root_id]!r}, got {grandchild_chain!r}"
    )
    assert set(grandchild["ancestorDomainUnitIds"]) == set(grandchild_chain), (
        f"CreateDomainUnit reported ancestorDomainUnitIds={grandchild['ancestorDomainUnitIds']!r} "
        f"for the grandchild but the independently-walked chain is {grandchild_chain!r}"
    )


# ===== helpers =====
def _walk_ancestors(dz, domain_id, start_id, root_id, max_hops=20):
    chain = []
    current = start_id
    for _ in range(max_hops):
        chain.append(current)
        if current == root_id:
            return chain
        node = dz.get_domain_unit(domainIdentifier=domain_id, identifier=current)
        current = node["parentDomainUnitId"]
    raise AssertionError(f"ancestor walk exceeded {max_hops} hops without reaching root {root_id!r}: {chain!r}")


def _safe(fn, deadline_s=60.0):
    """Teardown: a resource already gone is fine; ConflictException (a dependent resource is still
    being released) is retried to a deadline; every other error raises."""
    def _wrapped():
        from botocore.exceptions import ClientError

        deadline = time.monotonic() + deadline_s
        while True:
            try:
                fn()
                return
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code in ("ResourceNotFoundException", "NoSuchEntity"):
                    return
                if code != "ConflictException" or time.monotonic() >= deadline:
                    raise
            time.sleep(2)

    return _wrapped


def _create_domain(ctx):
    dz = ctx.client("datazone")
    role_arn = _create_domain_execution_role(ctx)
    name = ctx.unique_name("sim2real-dz-domain-")
    created = _create_domain_call(dz, name, role_arn)
    domain_id = created["id"]
    ctx.on_cleanup(
        _safe(lambda: dz.delete_domain(identifier=domain_id, cascadeDelete=True))
    )
    return _wait_domain_available(ctx, domain_id)


def _create_domain_execution_role(ctx):

    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-dz-exec-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "datazone.amazonaws.com"},
                "Action": ["sts:AssumeRole", "sts:TagSession", "sts:SetContext"],
            }
        ],
    }
    role = _create_role_with_retry(iam, role_name, trust_policy)
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(_safe(lambda: iam.delete_role(RoleName=role_name)))
    return role_arn


def _create_role_with_retry(iam, role_name, trust_policy, timeout_s=60.0):
    import json

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
        except Exception as exc:
            last_exc = exc
            time.sleep(3)
    raise last_exc


def _create_domain_call(dz, name, role_arn, timeout_s=60.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return dz.create_domain(name=name, domainExecutionRole=role_arn)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("ValidationException", "AccessDeniedException"):
                last_exc = exc
                time.sleep(3)
                continue
            raise
    raise last_exc


def _wait_domain_available(ctx, domain_id, timeout_s=900.0):
    dz = ctx.client("datazone")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = dz.get_domain(identifier=domain_id)
        last = resp
        if resp["status"] == "AVAILABLE":
            return resp
        if resp["status"] == "CREATION_FAILED":
            raise AssertionError(f"domain {domain_id} creation failed: {resp}")
        time.sleep(5)
    raise AssertionError(f"domain {domain_id} did not become AVAILABLE in time: {last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
