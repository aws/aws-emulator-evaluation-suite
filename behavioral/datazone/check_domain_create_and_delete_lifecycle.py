"""domain-create-and-delete-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "domain-create-and-delete-lifecycle"
GROUP = "state-machine"
SERVICES = ["datazone"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDomain transitions CREATING->AVAILABLE; DeleteDomain drives it to DELETED/gone and unusable."""
    dz = ctx.client("datazone")
    role_arn = _create_domain_execution_role(ctx)
    name = ctx.unique_name("sim2real-dz-domain-")
    created = _create_domain_call(dz, name, role_arn)
    domain_id = created["id"]

    def _cleanup():
        try:
            dz.delete_domain(identifier=domain_id, skipDeletionCheck=True)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    domain = _wait_domain_available(ctx, domain_id)
    assert domain["status"] == "AVAILABLE", f"expected AVAILABLE, got {domain['status']!r}"
    assert domain["arn"], f"expected a non-empty arn, got {domain.get('arn')!r}"
    assert domain["rootDomainUnitId"], (
        f"expected a non-empty rootDomainUnitId, got {domain.get('rootDomainUnitId')!r}"
    )

    delete_resp = dz.delete_domain(identifier=domain_id, skipDeletionCheck=True)
    # a domain with no child resources (this one) deletes synchronously and reports DELETED
    # immediately; one with children would still be mid-flight as DELETING
    assert delete_resp["status"] in ("DELETING", "DELETED"), (
        f"expected DELETING or DELETED, got {delete_resp['status']!r}"
    )

    gone = _wait_domain_deleted(ctx, domain_id)

    # the delete is unusable a second time: re-deleting the same id must fail, never succeed again.
    # Both codes mean "not there any more": ResourceNotFoundException, or, when the caller's own
    # tag-based authorization condition cannot evaluate on the gone domain, a bare
    # AccessDeniedException with an empty message.
    redelete_code, redelete_message = _error(
        lambda: dz.delete_domain(identifier=domain_id, skipDeletionCheck=True)
    )
    assert redelete_code in ("ResourceNotFoundException", "AccessDeniedException"), (
        f"expected ResourceNotFoundException or AccessDeniedException re-deleting an "
        f"already-deleted domain, got {redelete_code!r}"
    )
    if redelete_code == "AccessDeniedException":
        assert redelete_message == "", (
            f"expected an empty AccessDeniedException message re-deleting an already-deleted "
            f"domain, got {redelete_message!r}"
        )

    # terminal, independent read at the destination: the domain is gone, not merely out of AVAILABLE
    if gone:
        read_code, read_message = _error(lambda: dz.get_domain(identifier=domain_id))
        assert read_code in ("ResourceNotFoundException", "AccessDeniedException"), (
            f"expected ResourceNotFoundException or AccessDeniedException reading the deleted "
            f"domain, got {read_code!r}"
        )
        if read_code == "AccessDeniedException":
            assert read_message == "", (
                f"expected an empty AccessDeniedException message reading the deleted domain, "
                f"got {read_message!r}"
            )
    else:
        final = _read_domain_or_gone(dz, domain_id)
        assert final is None or final["status"] == "DELETED", (
            f"expected the domain gone or DELETED, got {final}"
        )


def _create_domain_execution_role(ctx):
    """Create a dedicated IAM role to use as the domain execution role.

    The caller's own credentials are not reliably backed by an assumable role
    (an IAM user has none to adopt), so a fresh, purpose-built role is
    created and torn down with the domain rather than derived from STS.
    """
    import json

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
    role = _create_role_with_retry(iam, role_name, json.dumps(trust_policy))
    role_arn = role["Role"]["Arn"]

    def _cleanup_role():
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup_role)
    return role_arn


def _create_role_with_retry(iam, role_name, trust_policy_json, timeout_s=60.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return iam.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=trust_policy_json,
                Tags=[{"Key": "sim2real", "Value": CHECK}],
            )
        except ClientError as exc:
            last_exc = exc
            time.sleep(3)
    raise last_exc


def _create_domain_call(dz, name, role_arn, timeout_s=60.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return dz.create_domain(name=name, domainExecutionRole=role_arn, tags={"sim2real": CHECK})
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("ValidationException", "AccessDeniedException"):
                last_exc = exc
                time.sleep(3)
                continue
            raise
    raise last_exc


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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


def _read_domain_or_gone(dz, domain_id):
    """GetDomain, or None if the domain is gone.

    Observed on real AWS to surface as either ResourceNotFoundException or (once the domain's own
    tags are gone too) AccessDeniedException -- both mean the same thing here.
    """
    try:
        return dz.get_domain(identifier=domain_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] in ("ResourceNotFoundException", "AccessDeniedException"):
            return None
        raise


def _wait_domain_deleted(ctx, domain_id, timeout_s=900.0) -> bool:
    """Poll until the domain is DELETED or fully gone; raise on DELETION_FAILED or timeout.

    Returns True if the domain is fully gone (see `_read_domain_or_gone`), False if it settled
    into a readable terminal DELETED record.
    """
    dz = ctx.client("datazone")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = _read_domain_or_gone(dz, domain_id)
        if resp is None:
            return True
        last = resp
        if resp["status"] == "DELETED":
            return False
        if resp["status"] == "DELETION_FAILED":
            raise AssertionError(f"domain {domain_id} deletion failed: {resp}")
        time.sleep(5)
    raise AssertionError(f"domain {domain_id} was not deleted within {timeout_s}s; last saw {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
