"""form-type-asset-type-forms-round-trip."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "form-type-asset-type-forms-round-trip"
GROUP = "data-plane"
SERVICES = ["datazone"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A custom form type's schema flows through CreateAssetType.formsOutput to an asset's formsOutput content."""
    dz = ctx.client("datazone")
    domain = _create_domain(ctx)
    project = _create_project(ctx, domain["id"])

    form_name = ctx.unique_name("Sim2realOwnerForm").replace("-", "")
    # CreateFormType's smithy model carries NO `namespace` declaration: DataZone supplies the
    # namespace itself, and a hand-written one (the domain id) is rejected.
    smithy = f"structure {form_name} {{\n    owner: smithy.api#String\n}}"
    # status is NOT optional in practice: on AWS a form type created
    # without it lands DISABLED and CreateAssetType then answers
    # ValidationException("FormType Form#<domain>#<name> is not enabled").
    form = dz.create_form_type(
        domainIdentifier=domain["id"],
        name=form_name,
        model={"smithy": smithy},
        owningProjectIdentifier=project["id"],
        status="ENABLED",
    )

    def _delete_form_type():
        # DeleteFormType requires the latest revision to be DISABLED ("should be disabled to Delete").
        dz.create_form_type(
            domainIdentifier=domain["id"],
            name=form_name,
            model={"smithy": smithy},
            owningProjectIdentifier=project["id"],
            status="DISABLED",
        )
        dz.delete_form_type(domainIdentifier=domain["id"], formTypeIdentifier=form_name)

    ctx.on_cleanup(_safe(_delete_form_type))

    asset_type = dz.create_asset_type(
        domainIdentifier=domain["id"],
        name=ctx.unique_name("Sim2realAssetType"),
        formsInput={
            form_name: {"typeIdentifier": form_name, "typeRevision": form["revision"], "required": False}
        },
        owningProjectIdentifier=project["id"],
    )
    ctx.on_cleanup(
        _safe(lambda: dz.delete_asset_type(domainIdentifier=domain["id"], identifier=asset_type["name"]))
    )
    assert form_name in asset_type["formsOutput"], (
        f"expected form {form_name!r} in asset type formsOutput, got {list(asset_type['formsOutput'])}"
    )

    content = json.dumps({"owner": "sim2real-team"})
    asset = dz.create_asset(
        domainIdentifier=domain["id"],
        name=ctx.unique_name("sim2real-dz-asset-"),
        typeIdentifier=asset_type["name"],
        owningProjectIdentifier=project["id"],
        formsInput=[
            {
                "formName": form_name,
                "typeIdentifier": form_name,
                "typeRevision": form["revision"],
                "content": content,
            }
        ],
    )
    ctx.on_cleanup(_safe(lambda: dz.delete_asset(domainIdentifier=domain["id"], identifier=asset["id"])))

    got = dz.get_asset(domainIdentifier=domain["id"], identifier=asset["id"])
    matching = [f for f in got["formsOutput"] if f["formName"] == form_name]
    assert len(matching) == 1, (
        f"expected exactly one form named {form_name!r} in GetAsset formsOutput, "
        f"got {[f['formName'] for f in got['formsOutput']]}"
    )
    got_owner = json.loads(matching[0]["content"])["owner"]
    assert got_owner == "sim2real-team", (
        f"expected round-tripped form content owner='sim2real-team', got {got_owner!r}"
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
                Tags=[{"Key": "sim2real", "Value": CHECK}],
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
                name=name, domainExecutionRole=role_arn, tags={"sim2real": CHECK}
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


def _create_project_call(dz, kwargs, timeout_s=120.0):
    """CreateProject right after the domain turns AVAILABLE can fail with AccessDeniedException
    because DataZone's own service principal cannot yet assume the freshly created domain
    execution role (IAM trust propagation). On AWS, CreateProject
    answered "... is not authorized to perform: sts:AssumeRole on resource: .../sim2real-dz-exec-*"
    seconds after CreateDomain returned AVAILABLE. Retry, exactly as _create_domain_call already
    does for the same class of race."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return dz.create_project(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] in ("AccessDeniedException", "ValidationException"):
                last_exc = exc
                time.sleep(5)
                continue
            raise
    raise last_exc


def _create_project(ctx, domain_id, name=None, domain_unit_id=None):
    dz = ctx.client("datazone")
    name = name or ctx.unique_name("sim2real-dz-proj-")
    kwargs = {"domainIdentifier": domain_id, "name": name, "resourceTags": {"sim2real": CHECK}}
    if domain_unit_id:
        kwargs["domainUnitId"] = domain_unit_id
    resp = _create_project_call(dz, kwargs)
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
