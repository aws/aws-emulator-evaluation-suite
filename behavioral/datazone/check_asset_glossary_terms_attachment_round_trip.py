"""asset-glossary-terms-attachment-round-trip."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "asset-glossary-terms-attachment-round-trip"
GROUP = "data-plane"
SERVICES = ["datazone"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A glossary term attached at CreateAsset time shows up in the asset's glossaryTerms on GetAsset."""
    dz = ctx.client("datazone")
    domain = _create_domain(ctx)
    project = _create_project(ctx, domain["id"])
    asset_type = _create_minimal_asset_type(ctx, domain["id"], project["id"])

    glossary = dz.create_glossary(
        domainIdentifier=domain["id"],
        name=ctx.unique_name("sim2real-dz-glossary-"),
        owningProjectIdentifier=project["id"],
    )
    ctx.on_cleanup(
        _safe(lambda: _disable_then_delete(dz.update_glossary, dz.delete_glossary, domain["id"], glossary["id"]))
    )
    term = dz.create_glossary_term(
        domainIdentifier=domain["id"],
        glossaryIdentifier=glossary["id"],
        name=ctx.unique_name("sim2real-dz-term-"),
    )
    ctx.on_cleanup(
        _safe(lambda: _disable_then_delete(
            dz.update_glossary_term, dz.delete_glossary_term, domain["id"], term["id"]))
    )

    asset = dz.create_asset(
        domainIdentifier=domain["id"],
        name=ctx.unique_name("sim2real-dz-asset-"),
        typeIdentifier=asset_type["name"],
        owningProjectIdentifier=project["id"],
        glossaryTerms=[term["id"]],
    )
    ctx.on_cleanup(_safe(lambda: dz.delete_asset(domainIdentifier=domain["id"], identifier=asset["id"])))

    got = dz.get_asset(domainIdentifier=domain["id"], identifier=asset["id"])
    attached = got.get("glossaryTerms", [])
    assert term["id"] in attached, f"expected term {term['id']!r} in glossaryTerms, got {attached!r}"

    dz.delete_asset(domainIdentifier=domain["id"], identifier=asset["id"])
    gone_code, gone_message = _error(
        lambda: dz.get_asset(domainIdentifier=domain["id"], identifier=asset["id"])
    )
    assert gone_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException reading deleted asset, got {gone_code!r}"
    )
    expected = "The given Asset doesn't exist. Try creating Asset before accessing it."
    assert gone_message == expected, (
        f"expected {expected!r} reading deleted asset, got {gone_message!r}"
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
            return iam.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(trust_policy),
                Tags=[{"Key": "sim2real-check", "Value": CHECK}],
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
            return dz.create_domain(
                name=name, domainExecutionRole=role_arn, tags={"sim2real-check": CHECK}
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
    kwargs = {"domainIdentifier": domain_id, "name": name, "resourceTags": {"sim2real-check": CHECK}}
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


def _create_minimal_asset_type(ctx, domain_id, project_id):
    dz = ctx.client("datazone")
    resp = dz.create_asset_type(
        domainIdentifier=domain_id,
        name=ctx.unique_name("Sim2realAssetType"),
        formsInput={},
        owningProjectIdentifier=project_id,
    )
    ctx.on_cleanup(
        _safe(lambda: dz.delete_asset_type(domainIdentifier=domain_id, identifier=resp["name"]))
    )
    return resp


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
