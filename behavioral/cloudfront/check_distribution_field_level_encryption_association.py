"""distribution-field-level-encryption-association."""
from __future__ import annotations

import itertools
import subprocess
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

_COUNTER = itertools.count()
_NO_SUCH_FLE_CONFIG = "The specified field level encryption config does not exist."
_FLE_CONFIG_IN_USE = (
    "The field level encryption config is currently associated with a cache behavior. "
    "Please disassociate the config before deleting."
)

def _error(fn):
    """Call fn(); return the botocore (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to fail, but it succeeded: {result!r}")

def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description} after {timeout_s}s (last: {last!r})")

def _wait_distribution_deployed(cf, dist_id, timeout_s=1200, interval_s=15, etag_hint=None):
    """Poll GetDistribution until Status == 'Deployed'; return the latest ETag."""
    holder = {"etag": etag_hint}
    def probe():
        resp = cf.get_distribution(Id=dist_id)
        holder["etag"] = resp["ETag"]
        return resp["Distribution"]["Status"]
    _poll_until(probe, lambda status: status == "Deployed", timeout_s=timeout_s, interval_s=interval_s)
    return holder["etag"]

def _force_delete_distribution(cf, dist_id):
    try:
        cfg_resp = cf.get_distribution_config(Id=dist_id)
    except cf.exceptions.NoSuchDistribution:
        return
    cfg = cfg_resp["DistributionConfig"]
    etag = cfg_resp["ETag"]
    if cfg.get("Enabled"):
        cfg["Enabled"] = False
        etag = cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=cfg)["ETag"]
    etag = _wait_distribution_deployed(cf, dist_id, etag_hint=etag)
    cf.delete_distribution(Id=dist_id, IfMatch=etag)

def _caller_reference(ctx, prefix="cf"):
    return ctx.unique_name(f"sim2real-behav-{prefix}-") + f"-{next(_COUNTER)}"

def _minimal_distribution_config(ctx, comment="", enabled=True, origin_domain=None, origin_id="primary-origin", extra_origins=None):
    """Build a minimal-but-valid DistributionConfig with a single custom origin."""
    domain = origin_domain or f"{ctx.unique_name('sim2real-behav-origin-')}.example.com"
    origins = [{
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
    }]
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
            "CachePolicyId": "658327ea-f89d-4fab-a63d-7e88639e58f6",  # Managed-CachingOptimized
        },
    }

def _generate_rsa_public_key_pem() -> str:
    from fidelity_tests_runner import require_tools

    require_tools("openssl")
    priv = subprocess.run(["openssl", "genrsa", "2048"], capture_output=True, check=True).stdout
    pub = subprocess.run(["openssl", "rsa", "-pubout"], input=priv, capture_output=True, check=True).stdout
    return pub.decode("ascii")

def _create_public_key(cf, ctx, prefix="sim2real-behav-pk-"):
    pem = _generate_rsa_public_key_pem()
    name = ctx.unique_name(prefix)
    resp = cf.create_public_key(
        PublicKeyConfig={"CallerReference": name, "Name": name, "EncodedKey": pem}
    )
    key_id = resp["PublicKey"]["Id"]
    ctx.on_cleanup(lambda: _delete_public_key(cf, key_id))
    return key_id, name

def _delete_public_key(cf, key_id):
    try:
        etag = cf.get_public_key(Id=key_id)["ETag"]
    except cf.exceptions.NoSuchPublicKey:
        return
    cf.delete_public_key(Id=key_id, IfMatch=etag)

def _delete_fle_profile(cf, profile_id):
    try:
        etag = cf.get_field_level_encryption_profile(Id=profile_id)["ETag"]
    except cf.exceptions.NoSuchFieldLevelEncryptionProfile:
        return
    cf.delete_field_level_encryption_profile(Id=profile_id, IfMatch=etag)

def _delete_fle_config(cf, fle_id):
    try:
        etag = cf.get_field_level_encryption_config(Id=fle_id)["ETag"]
    except cf.exceptions.NoSuchFieldLevelEncryptionConfig:
        return
    cf.delete_field_level_encryption_config(Id=fle_id, IfMatch=etag)

CHECK = "distribution-field-level-encryption-association"
GROUP = 'field-level-encryption'
SERVICES = ['cloudfront']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DefaultCacheBehavior.FieldLevelEncryptionId round-trips through GetDistributionConfig, and an
    attached FieldLevelEncryptionConfig cannot be deleted (FieldLevelEncryptionConfigInUse) until
    the distribution referencing it is deleted; an unattached config deletes fine."""
    cf = ctx.client("cloudfront")
    key_id, _ = _create_public_key(cf, ctx, "sim2real-behav-fle-assoc-pk-")

    profile_name = ctx.unique_name("sim2real-behav-fle-assoc-profile-")
    profile_resp = cf.create_field_level_encryption_profile(
        FieldLevelEncryptionProfileConfig={
            "Name": profile_name,
            "CallerReference": profile_name,
            "Comment": "assoc test",
            "EncryptionEntities": {
                "Quantity": 1,
                "Items": [
                    {
                        "PublicKeyId": key_id,
                        "ProviderId": "sim2real-behav-provider",
                        "FieldPatterns": {"Quantity": 1, "Items": ["credit-card-number"]},
                    }
                ],
            },
        }
    )
    profile_id = profile_resp["FieldLevelEncryptionProfile"]["Id"]
    ctx.on_cleanup(lambda: _delete_fle_profile(cf, profile_id))

    def _new_fle_config(suffix):
        name = ctx.unique_name(f"sim2real-behav-fle-assoc-{suffix}-")
        resp = cf.create_field_level_encryption_config(
            FieldLevelEncryptionConfig={
                "CallerReference": name,
                "Comment": "assoc test",
                "ContentTypeProfileConfig": {
                    "ForwardWhenContentTypeIsUnknown": True,
                    "ContentTypeProfiles": {
                        "Quantity": 1,
                        "Items": [
                            {
                                "ContentType": "application/x-www-form-urlencoded",
                                "Format": "URLEncoded",
                                "ProfileId": profile_id,
                            }
                        ],
                    },
                },
                "QueryArgProfileConfig": {
                    "ForwardWhenQueryArgProfileIsUnknown": True,
                    "QueryArgProfiles": {"Quantity": 0, "Items": []},
                },
            }
        )
        return resp["FieldLevelEncryption"]["Id"], resp["ETag"]

    # Positive control: an unattached config deletes, so InUse below is due to the attachment.
    probe_id, probe_etag = _new_fle_config("probe")
    ctx.on_cleanup(lambda: _delete_fle_config(cf, probe_id))
    cf.delete_field_level_encryption_config(Id=probe_id, IfMatch=probe_etag)
    probe_gone, probe_gone_msg = _error(lambda: cf.get_field_level_encryption_config(Id=probe_id))
    assert probe_gone == "NoSuchFieldLevelEncryptionConfig", (
        f"positive control: deleting an unattached FieldLevelEncryptionConfig must succeed and "
        f"be independently confirmed gone; got {probe_gone!r}"
    )
    assert probe_gone_msg == _NO_SUCH_FLE_CONFIG, f"expected message {_NO_SUCH_FLE_CONFIG!r}, got {probe_gone_msg!r}"

    fle_id, _ = _new_fle_config("assoc")
    ctx.on_cleanup(lambda: _delete_fle_config(cf, fle_id))

    cfg = _minimal_distribution_config(ctx, comment="fle-assoc")
    cfg["DefaultCacheBehavior"] = {
        "TargetOriginId": "primary-origin",
        "ViewerProtocolPolicy": "https-only",
        "CachePolicyId": "658327ea-f89d-4fab-a63d-7e88639e58f6",
        "FieldLevelEncryptionId": fle_id,
    }
    dist_resp = cf.create_distribution_with_tags(
        DistributionConfigWithTags={
            "DistributionConfig": cfg,
            "Tags": {"Items": [{"Key": "sim2real-behav", "Value": CHECK}]},
        }
    )
    dist_id = dist_resp["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _force_delete_distribution(cf, dist_id))

    cfg_resp = cf.get_distribution_config(Id=dist_id)
    got_fle_id = cfg_resp["DistributionConfig"]["DefaultCacheBehavior"]["FieldLevelEncryptionId"]
    assert got_fle_id == fle_id, (
        f"DefaultCacheBehavior.FieldLevelEncryptionId must round-trip through "
        f"GetDistributionConfig: expected {fle_id!r}, got {got_fle_id!r}"
    )

    fle_etag = cf.get_field_level_encryption_config(Id=fle_id)["ETag"]
    code, message = _error(
        lambda: cf.delete_field_level_encryption_config(Id=fle_id, IfMatch=fle_etag)
    )
    assert code == "FieldLevelEncryptionConfigInUse", (
        f"expected FieldLevelEncryptionConfigInUse while attached to a distribution, got {code}"
    )
    assert message == _FLE_CONFIG_IN_USE, f"expected message {_FLE_CONFIG_IN_USE!r}, got {message!r}"

    still_there = cf.get_field_level_encryption_config(Id=fle_id)
    assert still_there["ETag"] == fle_etag, (
        f"a rejected delete must leave the config unchanged: expected ETag {fle_etag!r}, "
        f"got {still_there['ETag']!r}"
    )

    # Deleting the distribution detaches the config, so the identical delete now succeeds.
    _force_delete_distribution(cf, dist_id)
    restore_etag = cf.get_field_level_encryption_config(Id=fle_id)["ETag"]
    cf.delete_field_level_encryption_config(Id=fle_id, IfMatch=restore_etag)
    restored_gone, restored_gone_msg = _error(lambda: cf.get_field_level_encryption_config(Id=fle_id))
    assert restored_gone == "NoSuchFieldLevelEncryptionConfig", (
        f"detaching the config (deleting the distribution) must restore deletability; the "
        f"identical delete call must now succeed, got {restored_gone!r}"
    )
    assert restored_gone_msg == _NO_SUCH_FLE_CONFIG, f"expected message {_NO_SUCH_FLE_CONFIG!r}, got {restored_gone_msg!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
