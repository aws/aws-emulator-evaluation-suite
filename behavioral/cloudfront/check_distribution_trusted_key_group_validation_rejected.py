"""distribution-trusted-key-group-validation-rejected."""
from __future__ import annotations

import itertools
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

_COUNTER = itertools.count()
_TKG_ABSENT = "One or more of your trusted keygroups do not exist."
_TKG_BAD_QUANTITY = (
    "The specified quantity of TrustedKeyGroups (2) does not match the actual quantity "
    "supplied (1)."
)

# Managed-CachingOptimized — a stable AWS-managed cache policy id (reference data).
MANAGED_CACHING_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"


def _error(fn):
    """Run fn and return (code, message). Raises if fn unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"timed out waiting for {description} after {timeout_s}s (last: {last!r})"
    )


def _wait_distribution_deployed(cf, dist_id, timeout_s=1800, interval_s=15, etag_hint=None):
    """Poll GetDistribution until Status == 'Deployed'; return the latest ETag.

    A distribution deployment routinely takes several minutes, hence the long deadline.
    """
    holder = {"etag": etag_hint}

    def probe():
        resp = cf.get_distribution(Id=dist_id)
        holder["etag"] = resp["ETag"]
        return resp["Distribution"]["Status"]

    _poll_until(
        probe,
        lambda status: status == "Deployed",
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"distribution {dist_id} Status=Deployed",
    )
    return holder["etag"]


def _force_delete_distribution(cf, dist_id):
    """Teardown: disable if needed, wait for Deployed, delete with the current ETag."""
    cfg_resp = cf.get_distribution_config(Id=dist_id)
    cfg = cfg_resp["DistributionConfig"]
    etag = cfg_resp["ETag"]
    if cfg.get("Enabled"):
        cfg["Enabled"] = False
        etag = cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=cfg)["ETag"]
    etag = _wait_distribution_deployed(cf, dist_id, etag_hint=etag)
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


def _caller_reference(ctx, prefix="cf"):
    return ctx.unique_name(f"sim2real-behav-{prefix}-") + f"-{next(_COUNTER)}"


def _custom_origin(origin_id, domain):
    return {
        "Id": origin_id,
        "DomainName": domain,
        "CustomOriginConfig": {
            "HTTPPort": 80,
            "HTTPSPort": 443,
            "OriginProtocolPolicy": "https-only",
            "OriginSslProtocols": {"Quantity": 1, "Items": ["TLSv1.2"]},
            "OriginReadTimeout": 30,
            "OriginKeepaliveTimeout": 5,
        },
    }


def _minimal_distribution_config(
    ctx, comment="", enabled=False, origin_id="primary-origin", extra_origins=None
):
    """Minimal-but-valid DistributionConfig with a single custom origin.

    Enabled defaults to False: a disabled distribution still has to reach
    Deployed before DeleteDistribution is accepted, but teardown then skips the
    extra disable-and-redeploy round trip.
    """
    domain = f"{ctx.unique_name('sim2real-behav-origin-')}.example.com"
    origins = [_custom_origin(origin_id, domain)]
    if extra_origins:
        origins.extend(extra_origins)
    return {
        "CallerReference": _caller_reference(ctx),
        "Comment": comment,
        "Enabled": enabled,
        "Origins": {"Quantity": len(origins), "Items": origins},
        "DefaultCacheBehavior": {
            "TargetOriginId": origin_id,
            "ViewerProtocolPolicy": "redirect-to-https",
            "CachePolicyId": MANAGED_CACHING_OPTIMIZED,
        },
    }


def _create_distribution(cf, ctx, **kwargs):
    cfg = _minimal_distribution_config(ctx, **kwargs)
    resp = cf.create_distribution(DistributionConfig=cfg)
    dist_id = resp["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _force_delete_distribution(cf, dist_id))
    return resp


CHECK = "distribution-trusted-key-group-validation-rejected"
GROUP = 'security'
SERVICES = ['cloudfront']


def _generate_rsa_public_key_pem():
    """Fresh, structurally-valid RSA-2048 SPKI PEM for CreatePublicKey."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDistribution refuses a TrustedKeyGroups block naming a missing key group or with
    inconsistent Quantity/Enabled/Items, checking shape before resolving ids and creating nothing,
    while a consistent block on a real key group is accepted even with allow-all viewer protocol."""
    cf = ctx.client("cloudfront")

    key_name = ctx.unique_name("sim2real-behav-pk-tkg-")
    public_key = cf.create_public_key(
        PublicKeyConfig={
            "CallerReference": _caller_reference(ctx, prefix="pk"),
            "Name": key_name,
            "EncodedKey": _generate_rsa_public_key_pem(),
            "Comment": "sim2real trusted-key-group validation",
        }
    )
    public_key_id = public_key["PublicKey"]["Id"]

    def _delete_public_key():
        etag = cf.get_public_key(Id=public_key_id)["ETag"]
        cf.delete_public_key(Id=public_key_id, IfMatch=etag)

    ctx.on_cleanup(_delete_public_key)

    group = cf.create_key_group(
        KeyGroupConfig={
            "Name": ctx.unique_name("sim2real-behav-kg-tkg-"),
            "Items": [public_key_id],
            "Comment": "sim2real trusted-key-group validation",
        }
    )
    key_group_id = group["KeyGroup"]["Id"]

    def _delete_key_group():
        etag = cf.get_key_group(Id=key_group_id)["ETag"]
        cf.delete_key_group(Id=key_group_id, IfMatch=etag)

    ctx.on_cleanup(_delete_key_group)

    # A syntactically valid key-group id that names no key group.
    ghost_id = "8f4d1c2b-6a3e-4f5d-9b8c-1e2f3a4b5c6d"

    def _reject(comment, trusted_key_groups):
        cfg = _minimal_distribution_config(ctx, comment=comment)
        cfg["DefaultCacheBehavior"]["TrustedKeyGroups"] = trusted_key_groups
        return _error(lambda: cf.create_distribution(DistributionConfig=cfg))

    # 1. Well-formed but nonexistent key group id.
    code, msg = _reject(
        "sim2real tkg-absent", {"Enabled": True, "Quantity": 1, "Items": [ghost_id]}
    )
    assert code == "TrustedKeyGroupDoesNotExist", (
        "a TrustedKeyGroups entry that does not exist must be rejected with "
        f"TrustedKeyGroupDoesNotExist, got {code!r}: {msg!r}"
    )
    assert msg == _TKG_ABSENT, f"expected message {_TKG_ABSENT!r}, got {msg!r}"

    # 2. Quantity disagreeing with the Items length. Note the item is the SAME nonexistent
    #    id as leg 1, and yet the answer is the shape error, not TrustedKeyGroupDoesNotExist:
    #    CloudFront validates the block's consistency BEFORE resolving the ids inside it.
    qty_code, qty_msg = _reject(
        "sim2real tkg-badqty", {"Enabled": True, "Quantity": 2, "Items": [ghost_id]}
    )
    assert qty_code == "InconsistentQuantities", (
        "a TrustedKeyGroups Quantity that does not match the Items length must be rejected "
        f"with InconsistentQuantities, got {qty_code!r}: {qty_msg!r}"
    )
    assert qty_msg == _TKG_BAD_QUANTITY, (
        f"the refusal must name the member and both counts it compared, got {qty_msg!r}"
    )
    assert qty_code != code, (
        f"the quantity error must be distinct from the id-resolution error {code!r} -- an "
        f"emulator that collapses them loses the ordering this leg pins"
    )

    # 3. Enabled with nothing to trust: the first direction of the Enabled/Items rule.
    empty_code, empty_msg = _reject(
        "sim2real tkg-empty", {"Enabled": True, "Quantity": 0, "Items": []}
    )
    assert empty_code == "InvalidArgument", (
        f"TrustedKeyGroups enabled with no items must be rejected with InvalidArgument, "
        f"got {empty_code!r}: {empty_msg!r}"
    )
    assert empty_msg == "The parameter TrustedKeyGroups must contain items if enabled.", (
        f"InvalidArgument is CloudFront's catch-all, so the message is what attributes the "
        f"refusal to the Enabled/Items rule; got {empty_msg!r}"
    )

    # 4. ...and the other direction: items present while disabled. Again a nonexistent id
    #    that is never resolved, because the shape rule fires first.
    off_code, off_msg = _reject(
        "sim2real tkg-offitems", {"Enabled": False, "Quantity": 1, "Items": [ghost_id]}
    )
    assert off_code == "InvalidArgument", (
        f"TrustedKeyGroups disabled but carrying items must be rejected with "
        f"InvalidArgument, got {off_code!r}: {off_msg!r}"
    )
    assert off_msg == "The parameter TrustedKeyGroups must not contain items if disabled.", (
        f"the refusal must state the disabled direction of the rule, got {off_msg!r}"
    )
    assert off_msg != empty_msg, (
        "the two directions of the Enabled/Items rule must be reported distinctly, both "
        f"got {off_msg!r}"
    )

    # Effect absent: none of the four rejected creates left a distribution behind.
    rejected_comments = {
        "sim2real tkg-absent",
        "sim2real tkg-badqty",
        "sim2real tkg-empty",
        "sim2real tkg-offitems",
    }
    leaked = []
    for page in cf.get_paginator("list_distributions").paginate():
        for item in page["DistributionList"].get("Items", []) or []:
            if item.get("Comment") in rejected_comments:
                leaked.append((item.get("Comment"), item["Id"]))
    assert not leaked, f"rejected creates must not leave distributions behind, found {leaked}"

    # ...and the key group itself is untouched by the rejected creates.
    assert cf.get_key_group(Id=key_group_id)["KeyGroup"]["KeyGroupConfig"]["Items"] == (
        [public_key_id]
    ), "the key group must be unchanged by the rejected creates"

    # 5. Control: a consistent block naming a real key group is accepted, even with
    #    ViewerProtocolPolicy=allow-all: CloudFront does not couple signed URLs to HTTPS.
    ok = _minimal_distribution_config(ctx, comment="sim2real tkg-ok")
    ok["DefaultCacheBehavior"]["TrustedKeyGroups"] = {
        "Enabled": True,
        "Quantity": 1,
        "Items": [key_group_id],
    }
    ok["DefaultCacheBehavior"]["ViewerProtocolPolicy"] = "allow-all"
    created = cf.create_distribution(DistributionConfig=ok)
    dist_id = created["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _force_delete_distribution(cf, dist_id))

    stored = cf.get_distribution_config(Id=dist_id)["DistributionConfig"]
    tkg = stored["DefaultCacheBehavior"]["TrustedKeyGroups"]
    assert tkg["Enabled"] is True, tkg
    assert tkg["Items"] == [key_group_id], f"expected [{key_group_id}], got {tkg.get('Items')}"
    assert tkg["Quantity"] == 1, tkg
    assert stored["DefaultCacheBehavior"]["ViewerProtocolPolicy"] == "allow-all", (
        "CloudFront accepts trusted key groups over plain HTTP and must store the policy "
        f"verbatim, got {stored['DefaultCacheBehavior'].get('ViewerProtocolPolicy')!r}"
    )
    # The distribution really is registered against the key group, which is the far-side
    # effect the rejected legs must NOT have produced. Polled, because CloudFront resolves
    # ActiveTrustedKeyGroups asynchronously -- the wait is never the assertion.
    active = _poll_until(
        lambda: cf.get_distribution(Id=dist_id)["Distribution"].get(
            "ActiveTrustedKeyGroups", {}
        ),
        lambda a: [g["KeyGroupId"] for g in a.get("Items", []) or []] == [key_group_id],
        timeout_s=300,
        interval_s=10,
        description=f"ActiveTrustedKeyGroups resolving to [{key_group_id}]",
    )
    assert active["Enabled"] is True, active
    assert [g["KeyGroupId"] for g in active["Items"]] == [key_group_id], active

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
