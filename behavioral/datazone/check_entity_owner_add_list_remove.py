"""entity-owner-add-list-remove."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "entity-owner-add-list-remove"
GROUP = "policy"
SERVICES = ["datazone"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AddEntityOwner adds a user owner visible via ListEntityOwners; RemoveEntityOwner removes it."""
    dz = ctx.client("datazone")
    domain = _create_domain(ctx)
    root_id = domain["rootDomainUnitId"]

    domain_unit = dz.create_domain_unit(
        domainIdentifier=domain["id"],
        name=ctx.unique_name("sim2real-dz-du-"),
        parentDomainUnitIdentifier=root_id,
    )
    ctx.on_cleanup(
        _safe(lambda: dz.delete_domain_unit(domainIdentifier=domain["id"], identifier=domain_unit["id"]))
    )

    baseline_owners = dz.list_entity_owners(
        domainIdentifier=domain["id"], entityType="DOMAIN_UNIT", entityIdentifier=domain_unit["id"]
    )["owners"]
    baseline_user_ids = {o["user"]["userId"] for o in baseline_owners if "user" in o}

    owner_role_arn = _create_owner_role(ctx)
    dz.add_entity_owner(
        domainIdentifier=domain["id"],
        entityType="DOMAIN_UNIT",
        entityIdentifier=domain_unit["id"],
        owner={"user": {"userIdentifier": owner_role_arn}},
    )

    owners = dz.list_entity_owners(
        domainIdentifier=domain["id"], entityType="DOMAIN_UNIT", entityIdentifier=domain_unit["id"]
    )["owners"]
    user_ids = {o["user"]["userId"] for o in owners if "user" in o}
    # DataZone resolves the IAM ARN into its own internal user id, which the caller cannot
    # predict, so the new owner is identified by set difference from the baseline.
    new_ids = user_ids - baseline_user_ids
    assert len(new_ids) == 1, (
        f"expected exactly one new owner after AddEntityOwner({owner_role_arn}): "
        f"baseline={baseline_user_ids}, got={user_ids}"
    )
    assert user_ids == baseline_user_ids | new_ids, (
        f"expected owners to be exactly baseline plus the new owner: "
        f"baseline={baseline_user_ids}, new={new_ids}, got={user_ids}"
    )

    dz.remove_entity_owner(
        domainIdentifier=domain["id"],
        entityType="DOMAIN_UNIT",
        entityIdentifier=domain_unit["id"],
        owner={"user": {"userIdentifier": owner_role_arn}},
    )
    owners_after = dz.list_entity_owners(
        domainIdentifier=domain["id"], entityType="DOMAIN_UNIT", entityIdentifier=domain_unit["id"]
    )["owners"]
    user_ids_after = {o["user"]["userId"] for o in owners_after if "user" in o}
    assert user_ids_after == baseline_user_ids, (
        f"expected owners to return to baseline {baseline_user_ids} after remove, "
        f"got {user_ids_after}"
    )


# ===== helpers =====
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
    created = _create_domain_call(dz, name, role_arn, tags={"sim2real": "true"})
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
    role = _create_role_with_retry(
        iam, role_name, trust_policy, tags=[{"Key": "sim2real", "Value": "true"}]
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(_safe(lambda: iam.delete_role(RoleName=role_name)))
    return role_arn


def _create_owner_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-dz-owner-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "datazone.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = _create_role_with_retry(
        iam, role_name, trust_policy, tags=[{"Key": "sim2real", "Value": "true"}]
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(_safe(lambda: iam.delete_role(RoleName=role_name)))
    return role_arn


def _create_role_with_retry(iam, role_name, trust_policy, tags=None, timeout_s=60.0):
    import json

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return iam.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(trust_policy),
                Tags=tags or [],
            )
        except Exception as exc:
            last_exc = exc
            time.sleep(3)
    raise last_exc


def _create_domain_call(dz, name, role_arn, tags=None, timeout_s=60.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return dz.create_domain(name=name, domainExecutionRole=role_arn, tags=tags or {})
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
