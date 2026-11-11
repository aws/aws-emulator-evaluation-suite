"""project-lifecycle-transitions."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "project-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["datazone"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateProject starts ACTIVE, UpdateProject persists edits, DeleteProject removes it."""
    dz = ctx.client("datazone")
    domain = _create_domain(ctx)
    project = _create_project(ctx, domain["id"])

    created = dz.get_project(domainIdentifier=domain["id"], identifier=project["id"])
    assert created["projectStatus"] == "ACTIVE", (
        f"expected ACTIVE on create, got {created['projectStatus']!r}"
    )

    dz.update_project(
        domainIdentifier=domain["id"], identifier=project["id"], description="sim2real-updated"
    )
    got = dz.get_project(domainIdentifier=domain["id"], identifier=project["id"])
    assert got["description"] == "sim2real-updated", (
        f"expected description 'sim2real-updated' after UpdateProject, got {got['description']!r}"
    )
    assert got["projectStatus"] == "ACTIVE", (
        f"expected ACTIVE to persist across UpdateProject, got {got['projectStatus']!r}"
    )

    dz.delete_project(domainIdentifier=domain["id"], identifier=project["id"], skipDeletionCheck=True)
    code, message = _error(lambda: dz.get_project(domainIdentifier=domain["id"], identifier=project["id"]))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from GetProject after delete, got {code!r}"
    )
    assert message == "Project not found", (
        f"expected 'Project not found' from GetProject after delete, got {message!r}"
    )

    mutate_code, mutate_message = _error(
        lambda: dz.update_project(
            domainIdentifier=domain["id"], identifier=project["id"], description="sim2real-post-delete"
        )
    )
    assert mutate_code == "ResourceNotFoundException", (
        f"expected UpdateProject on a deleted project to fail ResourceNotFoundException, got {mutate_code!r}"
    )
    assert mutate_message == "Project not found", (
        f"expected 'Project not found' from UpdateProject on a deleted project, got {mutate_message!r}"
    )


def _create_domain(ctx):
    dz = ctx.client("datazone")
    role_arn = _create_domain_execution_role(ctx)
    name = ctx.unique_name("sim2real-dz-domain-")
    created = _create_domain_call(dz, name, role_arn)
    domain_id = created["id"]

    def _cleanup():
        try:
            dz.delete_domain(identifier=domain_id, skipDeletionCheck=True, cascadeDelete=True)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
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
        iam, role_name, trust_policy, tags=[{"Key": "sim2real-behavioral-tag", "Value": "true"}]
    )
    role_arn = role["Role"]["Arn"]

    def _cleanup_role():
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup_role)
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


def _create_project(ctx, domain_id, name=None, domain_unit_id=None, timeout_s=60.0):
    from botocore.exceptions import ClientError

    dz = ctx.client("datazone")
    name = name or ctx.unique_name("sim2real-dz-proj-")
    kwargs = {
        "domainIdentifier": domain_id,
        "name": name,
        "resourceTags": {"sim2real-behavioral-tag": "true"},
    }
    if domain_unit_id:
        kwargs["domainUnitId"] = domain_unit_id

    # DataZone's internal provisioning assumes the domain execution role created
    # moments earlier; its trust policy can lag IAM's propagation, so CreateProject
    # transiently 403s until it catches up.
    deadline = time.monotonic() + timeout_s
    last_exc = None
    resp = None
    while time.monotonic() < deadline:
        try:
            resp = dz.create_project(**kwargs)
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "AccessDeniedException":
                last_exc = exc
                time.sleep(3)
                continue
            raise
    if resp is None:
        raise last_exc
    project_id = resp["id"]

    def _cleanup():
        try:
            dz.delete_project(domainIdentifier=domain_id, identifier=project_id, skipDeletionCheck=True)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return resp


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
