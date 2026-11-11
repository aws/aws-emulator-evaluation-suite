"""form-type-delete-in-use-conflict-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "form-type-delete-in-use-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["datazone"]

FORM_TYPE_NOT_FOUND = "The given FormType doesn't exist. Try creating FormType before accessing it."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteFormType on a form type in use by an asset is rejected while a disabled, unused one deletes cleanly."""
    dz = ctx.client("datazone")
    domain = _create_domain(ctx)
    project = _create_project(ctx, domain["id"])

    # positive control: a disabled, unused form type deletes cleanly.
    # DeleteFormType always requires the LATEST revision to be DISABLED first, regardless of use --
    # confirmed against real AWS: an ENABLED type is rejected with ValidationException("should be
    # disabled to Delete"), not the ConflictException this check is about.
    unused_name = ctx.unique_name("Sim2realUnusedForm").replace("-", "")
    unused_smithy = f"structure {unused_name} {{\n    note: smithy.api#String\n}}"
    dz.create_form_type(
        domainIdentifier=domain["id"],
        name=unused_name,
        model={"smithy": unused_smithy},
        owningProjectIdentifier=project["id"],
        status="DISABLED",
    )
    dz.delete_form_type(domainIdentifier=domain["id"], formTypeIdentifier=unused_name)
    gone_code, gone_message = _error(
        lambda: dz.get_form_type(domainIdentifier=domain["id"], formTypeIdentifier=unused_name)
    )
    assert gone_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a deleted unused form type, got {gone_code!r}"
    )
    assert gone_message == FORM_TYPE_NOT_FOUND, (
        f"expected {FORM_TYPE_NOT_FOUND!r} for a deleted unused form type, got {gone_message!r}"
    )

    # break: put a real asset (not just an asset type declaring the form) in front of the form type.
    # Confirmed against real AWS: an asset type alone referencing the form in formsInput does NOT
    # block delete -- only a materialized asset using that form does.
    form_name = ctx.unique_name("Sim2realForm").replace("-", "")
    smithy = f"structure {form_name} {{\n    owner: smithy.api#String\n}}"
    form = dz.create_form_type(
        domainIdentifier=domain["id"],
        name=form_name,
        model={"smithy": smithy},
        owningProjectIdentifier=project["id"],
        status="ENABLED",
    )

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
                "content": json.dumps({"owner": "sim2real-team"}),
            }
        ],
    )
    ctx.on_cleanup(_safe(lambda: dz.delete_asset(domainIdentifier=domain["id"], identifier=asset["id"])))

    # disable the in-use form type -- required before DataZone will evaluate the in-use conflict at all
    dz.create_form_type(
        domainIdentifier=domain["id"],
        name=form_name,
        model={"smithy": smithy},
        owningProjectIdentifier=project["id"],
        status="DISABLED",
    )

    code, message = _error(
        lambda: dz.delete_form_type(domainIdentifier=domain["id"], formTypeIdentifier=form_name)
    )
    assert code == "ConflictException", f"expected ConflictException while form type in use by an asset, got {code!r}: {message}"
    # DataZone spells the domain id with underscores inside its internal type keys
    type_domain = domain["id"].replace("-", "_")
    expected = (
        f"The following objects could not be deleted: type Form#{type_domain}#{form_name} "
        f"deletion prevented by type asset#{type_domain}#{asset_type['name']}. "
    )
    assert message == expected, (
        f"expected the conflict message {expected!r} naming the blocking asset type, got {message!r}"
    )

    still_there = dz.get_form_type(domainIdentifier=domain["id"], formTypeIdentifier=form_name)
    assert still_there["name"] == form_name, (
        f"expected {form_name!r} to survive the rejected delete, got {still_there.get('name')!r}"
    )

    # restore: remove what references the form type, then the identical delete must now succeed
    dz.delete_asset(domainIdentifier=domain["id"], identifier=asset["id"])
    dz.delete_asset_type(domainIdentifier=domain["id"], identifier=asset_type["name"])
    dz.delete_form_type(domainIdentifier=domain["id"], formTypeIdentifier=form_name)

    restored_gone_code, restored_gone_message = _error(
        lambda: dz.get_form_type(domainIdentifier=domain["id"], formTypeIdentifier=form_name)
    )
    assert restored_gone_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException once the referencing asset and asset type are removed "
        f"and the form type deleted, got {restored_gone_code!r}"
    )
    assert restored_gone_message == FORM_TYPE_NOT_FOUND, (
        f"expected {FORM_TYPE_NOT_FOUND!r} once the form type is deleted, got {restored_gone_message!r}"
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


def _create_project(ctx, domain_id, name=None, domain_unit_id=None):
    dz = ctx.client("datazone")
    name = name or ctx.unique_name("sim2real-dz-proj-")
    kwargs = {"domainIdentifier": domain_id, "name": name}
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
