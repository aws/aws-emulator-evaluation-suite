"""verify-dns-configuration-entity-not-found-rejected."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "verify-dns-configuration-entity-not-found-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]

_CACHING_OPTIMIZED_POLICY_ID = "658327ea-f89d-4fab-a63d-7e88639e58f6"
_MANAGED_TAG = {"Items": [{"Key": "sim2real:managed", "Value": "true"}]}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """VerifyDnsConfiguration returns a DnsConfigurationList entry for a real tenant's own domain, and fails with
    EntityNotFound "The specified distribution tenant doesn't exist." for two never-created tenant identifiers."""
    # One teardown deadline per run, started by the first teardown that runs.
    teardown_deadline: dict = {}
    cf = ctx.client("cloudfront")

    dist_id = _create_multitenant_distribution(ctx, teardown_deadline)
    domain = f"{ctx.unique_name('sim2real-cf-vdc-')}.com".lower()
    tenant = _create_distribution_tenant(ctx, dist_id, domain)
    ok = cf.verify_dns_configuration(Domain=domain, Identifier=tenant["Id"])
    entries = ok.get("DnsConfigurationList", [])
    matches = [e for e in entries if e.get("Domain") == domain]
    assert matches, f"positive control: no DnsConfiguration entry for {domain!r} in {entries!r}"

    # Break: a distribution tenant identifier that was never created.
    bogus_identifier_a = ctx.unique_name("sim2real-cf-no-such-tenant-a-")
    code_a, code_a_message = _error(
        lambda: cf.verify_dns_configuration(Identifier=bogus_identifier_a, Domain="unrelated-a.example.com")
    )
    assert code_a == "EntityNotFound", code_a
    expected_message = "The specified distribution tenant doesn't exist."
    assert code_a_message == expected_message, f"expected message {expected_message!r}, got {code_a_message!r}"

    # A second, independently bogus identifier gets the same treatment --
    # this is a genuine lookup-miss contract, not a fluke of one string.
    bogus_identifier_b = ctx.unique_name("sim2real-cf-no-such-tenant-b-")
    code_b, code_b_message = _error(
        lambda: cf.verify_dns_configuration(Identifier=bogus_identifier_b, Domain="unrelated-b.example.com")
    )
    assert code_b == "EntityNotFound", code_b
    assert code_b_message == expected_message, f"expected message {expected_message!r}, got {code_b_message!r}"


def _error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected success raises, so a
    target that accepts what AWS refuses fails loudly instead of reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _create_multitenant_distribution(ctx, teardown_deadline) -> str:
    cf = ctx.client("cloudfront")
    ref = ctx.unique_name("sim2real-cf-vdc-mtd-")
    resp = cf.create_distribution_with_tags(
        DistributionConfigWithTags={
            "DistributionConfig": {
                "CallerReference": ref,
                "Comment": "sim2real-behav verify-dns-configuration-entity-not-found-rejected",
                "Enabled": True,
                "ConnectionMode": "tenant-only",
                "Origins": {
                    "Quantity": 1,
                    "Items": [
                        {
                            "Id": "primary-origin",
                            "DomainName": "origin.example.com",
                            "CustomOriginConfig": {
                                "HTTPPort": 80,
                                "HTTPSPort": 443,
                                "OriginProtocolPolicy": "https-only",
                                "OriginSslProtocols": {"Quantity": 1, "Items": ["TLSv1.2"]},
                            },
                        }
                    ],
                },
                "DefaultCacheBehavior": {
                    "TargetOriginId": "primary-origin",
                    "ViewerProtocolPolicy": "allow-all",
                    "CachePolicyId": _CACHING_OPTIMIZED_POLICY_ID,
                },
            },
            "Tags": _MANAGED_TAG,
        }
    )
    dist_id = resp["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _delete_distribution_fully(ctx, dist_id, teardown_deadline))
    return dist_id


# budget.cleanup_timeout for behavioral/cloudfront, one deadline shared by the teardowns.
_TEARDOWN_RETRY_S = 1800.0


def _delete_distribution_fully(ctx, dist_id: str, teardown_deadline) -> None:
    cf = ctx.client("cloudfront")
    deadline = teardown_deadline.setdefault("t", time.monotonic() + _TEARDOWN_RETRY_S - 120.0)
    while time.monotonic() < deadline:
        try:
            got = cf.get_distribution(Id=dist_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchDistribution":
                raise
            return
        dist = got["Distribution"]
        etag = got["ETag"]
        cfg = dist["DistributionConfig"]
        if cfg.get("Enabled"):
            cfg["Enabled"] = False
            try:
                cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=cfg)
            except ClientError as exc:
                if exc.response["Error"]["Code"] not in (
                    "EntityNotFound",
                    "NoSuchCachePolicy",
                    "NoSuchContinuousDeploymentPolicy",
                    "NoSuchDistribution",
                    "NoSuchFieldLevelEncryptionConfig",
                    "NoSuchOrigin",
                    "NoSuchOriginRequestPolicy",
                    "NoSuchRealtimeLogConfig",
                    "NoSuchResponseHeadersPolicy",
                    "TrustedKeyGroupDoesNotExist",
                    "TrustedSignerDoesNotExist",
                ):
                    raise
            time.sleep(3)
            continue
        if dist["Status"] == "Deployed":
            try:
                cf.delete_distribution(Id=dist_id, IfMatch=etag)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchDistribution":
                    raise
            return
        time.sleep(5)
    raise AssertionError(f"distribution {dist_id} was not deleted before the teardown deadline")


def _create_distribution_tenant(ctx, dist_id: str, domain: str) -> dict[str, Any]:
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-cf-vdc-tenant-")
    resp = cf.create_distribution_tenant(
        DistributionId=dist_id,
        Name=name,
        Domains=[{"Domain": domain}],
        Enabled=True,
        Tags=_MANAGED_TAG,
        ManagedCertificateRequest={
            "ValidationTokenHost": "self-hosted",
            "CertificateTransparencyLoggingPreference": "disabled",
            "PrimaryDomainName": domain,
        },
    )
    tenant = resp["DistributionTenant"]
    tenant_id = tenant["Id"]
    ctx.on_cleanup(lambda: _delete_distribution_tenant_fully(ctx, tenant_id))
    return tenant


def _delete_distribution_tenant_fully(ctx, tenant_id: str) -> None:
    cf = ctx.client("cloudfront")
    try:
        got = cf.get_distribution_tenant(Identifier=tenant_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFound":
            raise
        return
    tenant = got["DistributionTenant"]
    etag = got["ETag"]
    if tenant.get("Enabled"):
        try:
            upd = cf.update_distribution_tenant(Id=tenant_id, IfMatch=etag, Enabled=False)
            etag = upd["ETag"]
        except ClientError:
            try:
                got = cf.get_distribution_tenant(Identifier=tenant_id)
                etag = got["ETag"]
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "EntityNotFound":
                    raise
                return
    try:
        cf.delete_distribution_tenant(Id=tenant_id, IfMatch=etag)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

