"""domain-duplicate-name-conflict-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "domain-duplicate-name-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["datazone"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDomain with a name already in use in the account is rejected; no duplicate is created."""
    dz = ctx.client("datazone")
    name = ctx.unique_name("sim2real-dz-dup-")
    role_arn = _create_domain_execution_role(ctx)

    first = _create_domain_call(dz, name, role_arn)
    domain_id = first["id"]
    ctx.on_cleanup(
        _safe(lambda: dz.delete_domain(identifier=domain_id, cascadeDelete=True))
    )
    _wait_domain_available(ctx, domain_id)

    code, message = _error(lambda: dz.create_domain(name=name, domainExecutionRole=role_arn))
    assert code == "ConflictException", f"expected ConflictException for duplicate name, got {code}"
    expected = "Domain name already exists under this account, please use another one"
    assert message == expected, f"expected {expected!r} for duplicate name, got {message!r}"

    matches = _list_domains_by_name(dz, name)
    assert len(matches) == 1, f"expected exactly 1 domain named {name!r}, found {matches}"
    assert matches[0]["id"] == domain_id, f"expected surviving domain to be {domain_id}, got {matches[0]}"

    # positive control: a domain with a different (unique) name still succeeds
    control = _create_domain(ctx)
    assert control["status"] == "AVAILABLE", f"expected control domain AVAILABLE, got {control['status']}"


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


def _list_domains_by_name(dz, name, max_pages=25):
    matches = []
    next_token = None
    for _ in range(max_pages):
        kwargs = {"maxResults": 25}
        if next_token:
            kwargs["nextToken"] = next_token
        page = dz.list_domains(**kwargs)
        matches.extend(item for item in page["items"] if item["name"] == name)
        next_token = page.get("nextToken")
        if not next_token:
            break
    return matches


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
    role = _create_role_with_retry(
        iam, role_name, trust_policy, tags=[{"Key": "sim2real-behavioral-tag", "Value": "true"}]
    )
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

