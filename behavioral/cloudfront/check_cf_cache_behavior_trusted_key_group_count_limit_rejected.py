"""cf-cache-behavior-trusted-key-group-count-limit-rejected."""
from __future__ import annotations

import itertools
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

_COUNTER = itertools.count()

MANAGED_CACHING_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"

_TOO_MANY_KEY_GROUPS = (
    "TooManyKeyGroupsAssociatedToDistribution",
    "Processing your request will cause you to exceed the maximum number of key groups "
    "that can be associated to a distribution.",
)


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
    raise AssertionError(f"timed out waiting for {description} after {timeout_s}s (last: {last!r})")


def _wait_distribution_deployed(cf, dist_id, timeout_s=1800, interval_s=15, etag_hint=None):
    """Poll GetDistribution until Status == 'Deployed'; return the latest ETag."""
    holder = {"etag": etag_hint}

    def probe():
        resp = cf.get_distribution(Id=dist_id)
        holder["etag"] = resp["ETag"]
        return resp["Distribution"]["Status"]

    _poll_until(
        probe, lambda status: status == "Deployed", timeout_s=timeout_s, interval_s=interval_s,
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


def _force_delete(get_fn, delete_fn, resource_id):
    """ETag-guarded delete of a CloudFront policy-like resource."""
    resp = get_fn(Id=resource_id)
    delete_fn(Id=resource_id, IfMatch=resp["ETag"])


def _caller_reference(ctx, prefix="cf"):
    return ctx.unique_name(f"sim2real-behav-{prefix}-") + f"-{next(_COUNTER)}"


def _generate_rsa_public_key_pem():
    """Fresh, structurally-valid RSA-2048 SPKI PEM for CreatePublicKey."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def _s3_origin(origin_id: str, domain: str) -> dict:
    """A minimal S3-backed Origin; the bucket need not exist for config CRUD."""
    return {
        "Id": origin_id,
        "DomainName": domain,
        "S3OriginConfig": {"OriginAccessIdentity": ""},
    }


def _distribution_config(ctx, comment, trusted_key_group_ids, origin_id="origin"):
    domain = f"{ctx.unique_name('sim2real-behav-origin-')}.s3.us-east-1.amazonaws.com"
    return {
        "CallerReference": _caller_reference(ctx, "trust"),
        "Comment": comment,
        "Enabled": False,
        "Origins": {"Quantity": 1, "Items": [_s3_origin(origin_id, domain)]},
        "DefaultCacheBehavior": {
            "TargetOriginId": origin_id,
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": MANAGED_CACHING_OPTIMIZED,
            "TrustedKeyGroups": {
                "Enabled": True,
                "Quantity": len(trusted_key_group_ids),
                "Items": trusted_key_group_ids,
            },
        },
    }


CHECK = "cf-cache-behavior-trusted-key-group-count-limit-rejected"
GROUP = "security"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A cache behavior naming five distinct trusted key groups is rejected with
    TooManyKeyGroupsAssociatedToDistribution and creates no distribution, while the same
    behavior naming four of them is accepted and stores all four."""
    cf = ctx.client("cloudfront")

    group_ids = []
    for i in range(5):
        created_key = cf.create_public_key(PublicKeyConfig={
            "CallerReference": _caller_reference(ctx, "pk"),
            "Name": ctx.unique_name(f"sim2real-behav-pk{i}-"),
            "EncodedKey": _generate_rsa_public_key_pem(),
        })
        key_id = created_key["PublicKey"]["Id"]
        ctx.on_cleanup(lambda key_id=key_id: _force_delete(cf.get_public_key, cf.delete_public_key, key_id))

        created_group = cf.create_key_group(KeyGroupConfig={
            "Name": ctx.unique_name(f"sim2real-behav-kg{i}-"),
            "Items": [key_id],
        })
        group_id = created_group["KeyGroup"]["Id"]
        ctx.on_cleanup(lambda group_id=group_id: _force_delete(cf.get_key_group, cf.delete_key_group, group_id))
        group_ids.append(group_id)

    rejected_comment = "sim2real tkg-count-limit-5"
    code, msg = _error(lambda: cf.create_distribution(
        DistributionConfig=_distribution_config(ctx, rejected_comment, group_ids)
    ))
    want_code, want_msg = _TOO_MANY_KEY_GROUPS
    assert code == want_code, f"expected {want_code!r}, got {code!r}: {msg!r}"
    assert msg == want_msg, f"expected message {want_msg!r}, got {msg!r}"

    # Effect absent: the rejected create left no distribution behind.
    leaked = []
    for page in cf.get_paginator("list_distributions").paginate():
        for item in page["DistributionList"].get("Items", []) or []:
            if item.get("Comment") == rejected_comment:
                leaked.append(item["Id"])
    assert not leaked, f"the rejected create must not leave a distribution behind, found {leaked}"

    # Positive control: four distinct key groups on the same cache behavior are accepted.
    ok_comment = "sim2real tkg-count-limit-4"
    created = cf.create_distribution(
        DistributionConfig=_distribution_config(ctx, ok_comment, group_ids[:4])
    )
    dist_id = created["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _force_delete_distribution(cf, dist_id))

    _wait_distribution_deployed(cf, dist_id)
    got_cfg = cf.get_distribution_config(Id=dist_id)["DistributionConfig"]
    stored_items = got_cfg["DefaultCacheBehavior"]["TrustedKeyGroups"]["Items"]
    assert sorted(stored_items) == sorted(group_ids[:4]), stored_items


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
