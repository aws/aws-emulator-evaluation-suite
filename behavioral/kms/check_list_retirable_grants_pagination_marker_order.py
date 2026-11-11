"""list-retirable-grants-pagination-marker-order."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "list-retirable-grants-pagination-marker-order"
GROUP = "ordering"
SERVICES = ["kms"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Paginating ListRetirableGrants (Marker, small Limit) returns a stable,
    non-overlapping sequence whose concatenated pages hold the same grants as a single
    unpaginated call for the same RetiringPrincipal (in any order; none is documented)."""
    kms = ctx.client("kms")
    iam = ctx.client("iam")

    key_id = _create_symmetric_key(ctx)
    # KMS validates that GranteePrincipal/RetiringPrincipal refer to real, existing
    # AWS principals (CreateGrant raises InvalidArnException otherwise), so create
    # per-run-unique IAM roles to scope ListRetirableGrants to principals nobody
    # else ever used - isolating the check from any other grants in the account.
    retiring_principal = _create_iam_role(ctx, iam, ctx.unique_name("sim2real-retiree-"))
    grantee_principal = _create_iam_role(ctx, iam, ctx.unique_name("sim2real-grantee-"))

    grant_ids: list[str] = []
    for _ in range(5):
        resp = _poll_until(
            lambda: _try_create_grant(
                kms, key_id, grantee_principal, retiring_principal
            ),
            lambda r: r is not None,
            timeout_s=120.0,
            interval_s=5.0,
        )
        grant_ids.append(resp["GrantId"])
    for gid in grant_ids:
        ctx.on_cleanup(lambda gid=gid: kms.retire_grant(KeyId=key_id, GrantId=gid))

    # Eventual consistency: grants are usually visible within a few minutes.
    reference = _poll_until(
        lambda: kms.list_retirable_grants(RetiringPrincipal=retiring_principal, Limit=100),
        lambda r: len(r["Grants"]) >= 5,
        timeout_s=300.0,
        interval_s=5.0,
    )
    assert reference["Truncated"] is False, (
        f"expected a single Limit=100 call to return all 5 grants unpaginated, "
        f"got Truncated={reference['Truncated']!r}"
    )
    reference_ids = [g["GrantId"] for g in reference["Grants"]]
    assert set(reference_ids) == set(grant_ids), (
        f"expected the unpaginated listing to contain exactly the created grants "
        f"{sorted(grant_ids)}, got {sorted(reference_ids)}"
    )
    assert len(reference_ids) == 5, (
        f"expected exactly 5 distinct grants for this retiring principal, got {len(reference_ids)}: {reference_ids}"
    )

    # Now walk the same principal's grants a page at a time with a small Limit and
    # confirm the concatenated pages reproduce the same grants with no overlap.
    paged_ids: list[str] = []
    seen: set[str] = set()
    marker = None
    for _ in range(20):
        kwargs: dict[str, Any] = {"RetiringPrincipal": retiring_principal, "Limit": 2}
        if marker:
            kwargs["Marker"] = marker
        page = kms.list_retirable_grants(**kwargs)
        page_ids = [g["GrantId"] for g in page["Grants"]]
        overlap = seen & set(page_ids)
        assert not overlap, f"pagination returned overlapping grant ids across pages: {overlap}"
        seen.update(page_ids)
        paged_ids.extend(page_ids)
        if not page.get("Truncated"):
            break
        marker = page["NextMarker"]
    else:
        raise AssertionError("ListRetirableGrants pagination never terminated (Truncated stayed true)")

    assert paged_ids == reference_ids or sorted(paged_ids) == sorted(reference_ids), (
        f"paginated grants {paged_ids} do not match unpaginated reference {reference_ids}"
    )


def _create_symmetric_key(ctx) -> str:
    kms = ctx.client("kms")
    resp = kms.create_key(
        Description=ctx.unique_name("sim2real-kms-grants-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": "list-retirable-grants-pagination-marker-order"}],
    )
    key_id = resp["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(
        lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    )
    return key_id


def _create_iam_role(ctx, iam, role_name: str) -> str:
    trust_policy = (
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
        '"Principal":{"Service":"kms.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
    )
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "sim2real", "Value": "list-retirable-grants-pagination-marker-order"}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return resp["Role"]["Arn"]


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float = 60.0,
    interval_s: float = 2.0,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _try_create_grant(kms, key_id, grantee_principal, retiring_principal):
    """Retry CreateGrant while the freshly-created IAM roles propagate; KMS
    rejects grants to a principal ARN it cannot yet resolve with
    InvalidArnException until IAM propagation catches up."""
    from botocore.exceptions import ClientError

    try:
        return kms.create_grant(
            KeyId=key_id,
            GranteePrincipal=grantee_principal,
            RetiringPrincipal=retiring_principal,
            Operations=["Encrypt"],
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "InvalidArnException":
            return None
        raise



if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
