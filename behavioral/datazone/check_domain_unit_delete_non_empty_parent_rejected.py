"""domain-unit-delete-non-empty-parent-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "domain-unit-delete-non-empty-parent-rejected"
GROUP = "overly-permissive"
SERVICES = ["datazone"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDomainUnit on a domain unit that still has a child unit is rejected until the child is gone."""
    dz = ctx.client("datazone")
    domain = _create_domain(ctx)
    root_id = domain["rootDomainUnitId"]

    parent = dz.create_domain_unit(
        domainIdentifier=domain["id"],
        name=ctx.unique_name("sim2real-dz-parent-"),
        parentDomainUnitIdentifier=root_id,
    )
    child = dz.create_domain_unit(
        domainIdentifier=domain["id"],
        name=ctx.unique_name("sim2real-dz-child-"),
        parentDomainUnitIdentifier=parent["id"],
    )

    _wait_child_listed(dz, domain["id"], parent["id"], child["id"])

    code, message = _error(
        lambda: dz.delete_domain_unit(domainIdentifier=domain["id"], identifier=parent["id"])
    )
    assert code == "ConflictException", (
        f"DeleteDomainUnit on a parent with a live child must be rejected with "
        f"ConflictException, got {code!r}"
    )
    expected = (
        f"The following objects could not be deleted: domainUnit {parent['id']} "
        f"deletion prevented by domainUnit {child['id']}. "
    )
    assert message == expected, (
        f"expected DeleteDomainUnit on a parent with a live child to say {expected!r}, got {message!r}"
    )

    still_there = dz.get_domain_unit(domainIdentifier=domain["id"], identifier=parent["id"])
    assert still_there["id"] == parent["id"], (
        f"parent domain unit {parent['id']} must still be readable after the rejected "
        f"delete, got {still_there!r}"
    )

    # positive control: once the child is removed, the parent can be deleted
    dz.delete_domain_unit(domainIdentifier=domain["id"], identifier=child["id"])
    dz.delete_domain_unit(domainIdentifier=domain["id"], identifier=parent["id"])

    # Real AWS denies rather than 404s a read on a just-deleted domain unit: a 90s poll never
    # once observed ResourceNotFoundException. Assert that measured contract, and freeze-detect
    # it across three independent reads rather than trusting a single sample.
    gone_codes = []
    for _ in range(3):
        gone_codes.append(
            _error(
                lambda: dz.get_domain_unit(domainIdentifier=domain["id"], identifier=parent["id"])
            )
        )
        time.sleep(2)
    denied = (
        "AccessDeniedException",
        "User is not permitted to perform operation: GetDomainUnit, or the requested resource does not exist",
    )
    assert gone_codes == [denied] * 3, (
        f"GetDomainUnit on a just-deleted domain unit must consistently deny access rather "
        f"than 404, got {gone_codes!r}"
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


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, because a target that
    accepts what real AWS refuses must not be reported as a mere code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _wait_child_listed(dz, domain_id, parent_id, child_id, timeout_s=90.0, interval_s=3.0, settle=4):
    """Bounded wait until the parent lists the child on `settle` consecutive reads, so the delete
    below sees a non-empty parent."""
    deadline = time.monotonic() + timeout_s
    listed = []
    streak = 0
    while time.monotonic() < deadline:
        listed = dz.list_domain_units_for_parent(
            domainIdentifier=domain_id, parentDomainUnitIdentifier=parent_id
        )["items"]
        streak = streak + 1 if any(item["id"] == child_id for item in listed) else 0
        if streak >= settle:
            return
        time.sleep(interval_s)
    raise AssertionError(
        f"child domain unit {child_id} not listed under parent {parent_id} on {settle} consecutive "
        f"reads within {timeout_s}s; last saw {listed!r}"
    )


def _mgmt_tags():
    return {"sim2real:managed": "true", "sim2real:prefix": "sim2real-dz"}


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
    role_tags = [{"Key": k, "Value": v} for k, v in _mgmt_tags().items()]
    role = _create_role_with_retry(iam, role_name, trust_policy, role_tags)
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(_safe(lambda: iam.delete_role(RoleName=role_name)))
    return role_arn


def _create_role_with_retry(iam, role_name, trust_policy, role_tags, timeout_s=60.0):
    import json

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return iam.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(trust_policy),
                Tags=role_tags,
            )
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
            return dz.create_domain(name=name, domainExecutionRole=role_arn, tags=_mgmt_tags())
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
