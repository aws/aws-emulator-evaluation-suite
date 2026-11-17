"""delete-key-group-trusted-by-distribution-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from behavioral_harness import tags

CHECK = "delete-key-group-trusted-by-distribution-rejected"
GROUP = "security"
SERVICES = ["cloudfront"]

_CACHING_DISABLED = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"  # AWS managed cache policy
_IN_USE_MESSAGE = (
    "The specified key group is currently associated with a cache behavior. "
    "Please disassociate the key group before deleting."
)


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _poll_until(probe, predicate, *, timeout_s, interval_s=5.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description} after {timeout_s}s (last: {last!r})")


def _wait_deployed(cf, dist_id, *, timeout_s=1200.0) -> str:
    holder = {"etag": ""}

    def probe() -> str:
        r = cf.get_distribution(Id=dist_id)
        holder["etag"] = r["ETag"]
        return r["Distribution"]["Status"]

    _poll_until(probe, lambda s: s == "Deployed", timeout_s=timeout_s, interval_s=10.0,
                description=f"distribution {dist_id} Deployed")
    return holder["etag"]


def _disable_and_delete_distribution(cf, dist_id) -> None:
    """Disable, wait for the change to deploy, then delete."""
    try:
        cfg_resp = cf.get_distribution_config(Id=dist_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchDistribution":
            return
        raise
    cfg, etag = cfg_resp["DistributionConfig"], cfg_resp["ETag"]
    if cfg.get("Enabled"):
        cfg["Enabled"] = False
        cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=cfg)
    etag = _wait_deployed(cf, dist_id)
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a refusal, the call succeeded: {result!r}")


@tags(
    "axis:rejection",
    "concern:negative-classes",
    "plane:control",
    "cap:c1",
)
def run(ctx) -> None:
    """DeleteKeyGroup refuses a key group a distribution trusts with ResourceInUse and the group
    survives intact, while an identical key group no distribution trusts deletes at once.
    """
    cf = ctx.client("cloudfront")

    name = ctx.unique_name("sim2real-behav-cfkgiu-pk-")
    pem = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    key_id = cf.create_public_key(PublicKeyConfig={
        "CallerReference": name, "Name": name, "EncodedKey": pem})["PublicKey"]["Id"]
    ctx.on_cleanup(_teardown(
        lambda: cf.delete_public_key(Id=key_id, IfMatch=cf.get_public_key(Id=key_id)["ETag"]),
        "NoSuchPublicKey"))

    group_ids = {}
    for label in ("trusted", "spare"):
        kg_id = cf.create_key_group(KeyGroupConfig={
            "Name": ctx.unique_name(f"sim2real-behav-cfkgiu-{label}-"), "Items": [key_id],
        })["KeyGroup"]["Id"]
        ctx.on_cleanup(_teardown(
            lambda k=kg_id: cf.delete_key_group(Id=k, IfMatch=cf.get_key_group(Id=k)["ETag"]),
            "NoSuchResource"))
        group_ids[label] = kg_id
    trusted_id = group_ids["trusted"]

    dist = cf.create_distribution(DistributionConfig={
        "CallerReference": ctx.unique_name("sim2real-behav-cfkgiu-cr-"),
        "Comment": "sim2real key group in use",
        "Enabled": False,
        "Origins": {"Quantity": 1, "Items": [{
            "Id": "origin",
            "DomainName": "origin.example.com",
            "CustomOriginConfig": {"HTTPPort": 80, "HTTPSPort": 443,
                                   "OriginProtocolPolicy": "https-only"},
        }]},
        "DefaultCacheBehavior": {
            "TargetOriginId": "origin",
            "ViewerProtocolPolicy": "https-only",
            "CachePolicyId": _CACHING_DISABLED,
            "TrustedKeyGroups": {"Enabled": True, "Quantity": 1, "Items": [trusted_id]},
        },
    })["Distribution"]
    dist_id = dist["Id"]
    # Registered after the key groups, so LIFO deletes the distribution first.
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(cf, dist_id))

    listed = []
    marker = ""
    while True:
        page = cf.list_distributions_by_key_group(KeyGroupId=trusted_id, Marker=marker)
        listed += page["DistributionIdList"].get("Items", [])
        marker = page["DistributionIdList"].get("NextMarker", "")
        if not marker:
            break
    assert listed == [dist_id], f"distributions trusting the key group: {listed!r}"

    before = cf.get_key_group(Id=trusted_id)
    code, msg = _error(lambda: cf.delete_key_group(Id=trusted_id, IfMatch=before["ETag"]))
    assert code == "ResourceInUse", f"expected ResourceInUse, got {code!r}: {msg!r}"
    assert msg == _IN_USE_MESSAGE, f"expected message {_IN_USE_MESSAGE!r}, got {msg!r}"

    after = cf.get_key_group(Id=trusted_id)
    assert after["ETag"] == before["ETag"], (
        f"the refused delete changed the key group's ETag: {before['ETag']!r} -> {after['ETag']!r}"
    )
    assert after["KeyGroup"]["KeyGroupConfig"]["Items"] == [key_id], (
        f"the refused delete changed the members: {after['KeyGroup']['KeyGroupConfig']!r}"
    )
    trusted_by = cf.get_distribution_config(Id=dist_id)["DistributionConfig"][
        "DefaultCacheBehavior"]["TrustedKeyGroups"]
    assert trusted_by.get("Items") == [trusted_id], f"distribution trust after refusal: {trusted_by!r}"

    spare_id = group_ids["spare"]
    cf.delete_key_group(Id=spare_id, IfMatch=cf.get_key_group(Id=spare_id)["ETag"])
    gone_code, gone_msg = _error(lambda: cf.get_key_group(Id=spare_id))
    assert gone_code == "NoSuchResource", f"expected NoSuchResource, got {gone_code!r}"
    assert gone_msg == "The specified key group does not exist.", (
        f"expected the not-found message, got {gone_msg!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
