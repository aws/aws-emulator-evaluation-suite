"""project-cross-domain-isolation-not-found."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "project-cross-domain-isolation-not-found"
GROUP = "overly-permissive"
SERVICES = ["datazone"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetProject scoped to a domain that does not own the project returns ResourceNotFoundException."""
    dz = ctx.client("datazone")
    domain_a = _create_domain(ctx)
    domain_b = _create_domain(ctx)
    project = _create_project(ctx, domain_a["id"])

    code, message = _error(
        lambda: dz.get_project(domainIdentifier=domain_b["id"], identifier=project["id"])
    )
    assert code == "ResourceNotFoundException", (
        f"GetProject for a project owned by {domain_a['id']!r} but scoped to the unrelated "
        f"domain {domain_b['id']!r} must be ResourceNotFoundException, got {code!r}"
    )
    assert message == "Project not found", (
        f"GetProject scoped to the unrelated domain {domain_b['id']!r} must say 'Project not found', "
        f"got {message!r}"
    )

    # positive control: the same lookup scoped to the owning domain succeeds
    got = dz.get_project(domainIdentifier=domain_a["id"], identifier=project["id"])
    assert got["id"] == project["id"], (
        f"positive control: GetProject scoped to the owning domain {domain_a['id']!r} must "
        f"return {project['id']!r}, got {got.get('id')!r}"
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
            return iam.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(trust_policy),
                Tags=[{"Key": "sim2real", "Value": "true"}],
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
                name=name,
                domainExecutionRole=role_arn,
                tags={"sim2real": "true"},
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
    kwargs = {"domainIdentifier": domain_id, "name": name, "resourceTags": {"sim2real": "true"}}
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
