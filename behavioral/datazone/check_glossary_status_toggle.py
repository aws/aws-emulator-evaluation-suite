"""glossary-status-toggle."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "glossary-status-toggle"
GROUP = "state-machine"
SERVICES = ["datazone"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A glossary is created ENABLED by default and UpdateGlossary flips it to DISABLED and back."""
    dz = ctx.client("datazone")
    domain = _create_domain(ctx)
    project = _create_project(ctx, domain["id"])

    glossary = dz.create_glossary(
        domainIdentifier=domain["id"],
        name=ctx.unique_name("sim2real-dz-glossary-"),
        owningProjectIdentifier=project["id"],
    )
    ctx.on_cleanup(
        _safe(lambda: _disable_then_delete(dz.update_glossary, dz.delete_glossary, domain["id"], glossary["id"]))
    )
    assert glossary["status"] == "ENABLED", f"expected ENABLED on create, got {glossary['status']!r}"

    dz.update_glossary(domainIdentifier=domain["id"], identifier=glossary["id"], status="DISABLED")
    got = dz.get_glossary(domainIdentifier=domain["id"], identifier=glossary["id"])
    assert got["status"] == "DISABLED", (
        f"expected DISABLED after UpdateGlossary(status=DISABLED), got {got['status']!r}"
    )

    dz.update_glossary(domainIdentifier=domain["id"], identifier=glossary["id"], status="ENABLED")
    got2 = dz.get_glossary(domainIdentifier=domain["id"], identifier=glossary["id"])
    assert got2["status"] == "ENABLED", (
        f"expected ENABLED after UpdateGlossary(status=ENABLED), got {got2['status']!r}"
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


def _disable_then_delete(update, delete, domain_id, identifier):
    """DataZone deletes a glossary or glossary term only once it is DISABLED."""
    update(domainIdentifier=domain_id, identifier=identifier, status="DISABLED")
    delete(domainIdentifier=domain_id, identifier=identifier)


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
    role = _create_role_with_retry(iam, role_name, trust_policy, tags=[{"Key": "sim2real-behavioral-tag", "Value": "true"}])
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(_safe(lambda: iam.delete_role(RoleName=role_name)))
    return role_arn


def _create_role_with_retry(iam, role_name, trust_policy, timeout_s=60.0, tags=None):
    import json

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            kwargs = {"RoleName": role_name, "AssumeRolePolicyDocument": json.dumps(trust_policy)}
            if tags:
                kwargs["Tags"] = tags
            return iam.create_role(**kwargs)
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
            return dz.create_domain(
                name=name, domainExecutionRole=role_arn, tags={"sim2real-behavioral-tag": "true"}
            )
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


def _create_project(ctx, domain_id, name=None, domain_unit_id=None):
    dz = ctx.client("datazone")
    name = name or ctx.unique_name("sim2real-dz-proj-")
    kwargs = {
        "domainIdentifier": domain_id,
        "name": name,
        "resourceTags": {"sim2real-behavioral-tag": "true"},
    }
    if domain_unit_id:
        kwargs["domainUnitId"] = domain_unit_id
    resp = dz.create_project(**kwargs)
    project_id = resp["id"]
    ctx.on_cleanup(
        _safe(
            lambda: dz.delete_project(
                domainIdentifier=domain_id, identifier=project_id, skipDeletionCheck=True
            )
        )
    )
    return resp


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
