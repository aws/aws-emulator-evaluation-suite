"""op-contract-deleteDistributionTenant."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deleteDistributionTenant"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]

_MANAGED_CACHING_DISABLED_ID = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDistributionTenant on a well-formed but unknown tenant id is refused with EntityNotFound and
    the exact message; on a real disabled tenant it succeeds, after which GetDistributionTenant and a
    second delete return the same EntityNotFound."""
    cf = ctx.client("cloudfront")
    origin_domain = f"{ctx.unique_name('sim2real-tenant-origin')}.example.com"

    try:
        dist = cf.create_distribution(
            DistributionConfig={
                "CallerReference": ctx.unique_name("sim2real-mt-dist-"),
                "Comment": "sim2real behavioral check (multi-tenant primary)",
                "Enabled": True,
                "ConnectionMode": "tenant-only",
                "Origins": {
                    "Quantity": 1,
                    "Items": [
                        {
                            "Id": "primary-origin",
                            "DomainName": origin_domain,
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
                    "CachePolicyId": _MANAGED_CACHING_DISABLED_ID,
                },
            }
        )
    except ClientError as exc:
        raise AssertionError(
            f"unreachable: multi-tenant primary distribution unavailable in this account: "
            f"{exc.response['Error']['Code']}"
        ) from exc

    dist_id = dist["Distribution"]["Id"]
    ctx.on_cleanup(lambda dist_id=dist_id: _cleanup_distribution(ctx, dist_id))

    domain = _unowned_domain(ctx, "sim2real-tenant")
    tenant = cf.create_distribution_tenant(
        DistributionId=dist_id,
        Name=ctx.unique_name("sim2real-tenant-")[:64],
        Domains=[{"Domain": domain}],
        Enabled=False,
        # Every distribution tenant needs a certificate; for a domain whose DNS the caller does not
        # control the managed certificate stays pending, but CreateDistributionTenant succeeds.
        ManagedCertificateRequest={"ValidationTokenHost": "self-hosted", "PrimaryDomainName": domain},
    )

    tenant_id = tenant["DistributionTenant"]["Id"]
    etag = tenant["ETag"]

    def _cleanup_tenant(tenant_id=tenant_id):
        try:
            fresh = cf.get_distribution_tenant(Identifier=tenant_id)
            cf.delete_distribution_tenant(Id=tenant_id, IfMatch=fresh["ETag"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "EntityNotFound":
                raise

    ctx.on_cleanup(_cleanup_tenant)

    # error boundary: a made-up tenant Id must have the "dt_"-prefixed shape and the IfMatch a
    # well-formed ETag (the real tenant's), or CloudFront refuses the request as malformed
    # (InvalidArgument, InvalidIfMatchVersion) before the not-found lookup this asserts.
    nf_code, nf_message = _error(
        lambda: cf.delete_distribution_tenant(
            Id=_fake_tenant_id(ctx), IfMatch=etag
        )
    )
    assert nf_code == "EntityNotFound", f"expected EntityNotFound, got {nf_code}"
    assert nf_message == "The specified distribution tenant doesn't exist.", (
        f"expected the exact refusal message, got {nf_message!r}"
    )

    # success path (tenant was created disabled, so no ResourceNotDisabled conflict)
    cf.delete_distribution_tenant(Id=tenant_id, IfMatch=etag)
    gone_code, gone_message = _error(lambda: cf.get_distribution_tenant(Identifier=tenant_id))
    assert gone_code == "EntityNotFound", f"expected EntityNotFound after delete, got {gone_code}"
    assert gone_message == "The specified distribution tenant doesn't exist.", (
        f"expected the exact refusal message, got {gone_message!r}"
    )

    # a mutation against the deleted Id also fails, not just a read
    redelete_code, redelete_message = _error(
        lambda: cf.delete_distribution_tenant(Id=tenant_id, IfMatch=etag)
    )
    assert redelete_code == "EntityNotFound", (
        f"expected EntityNotFound deleting an already-deleted tenant, got {redelete_code}"
    )
    assert redelete_message == "The specified distribution tenant doesn't exist.", (
        f"expected the exact refusal message, got {redelete_message!r}"
    )


def _fake_tenant_id(ctx) -> str:
    # Real tenant Ids are "dt_" + a 27-char alnum token (e.g.
    # "dt_3JMt4emPfoNaU2OJC2Vwo1T1f97"); anything a different shape is rejected as
    # malformed (InvalidArgument) before CloudFront even looks the Id up.
    raw = ctx.unique_name("x").lower()
    cleaned = "".join(ch for ch in raw if ch.isalnum())
    padded = (cleaned + "0" * 27)[:27]
    return f"dt_{padded}"


def _unowned_domain(ctx, label: str) -> str:
    # CloudFront rejects any *.example.com/.example.org/.example.net domain outright
    # with InvalidArgument ("Domain Name not allowed") -- those roots are IANA-reserved
    # documentation domains and CloudFront denylists them explicitly. A random,
    # unregistered .com name passes the same format/denylist check without requiring us
    # to actually own or DNS-validate it (CloudFront only validates ownership later, via
    # the pending managed-certificate TXT record).
    raw = ctx.unique_name(f"{label}-").lower()
    cleaned = "".join(ch if (ch.isalnum() or ch == "-") else "-" for ch in raw).strip("-")
    return f"{cleaned}.com"


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises,
    because an emulator accepting input real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _wait_distribution_deployed(ctx, dist_id, timeout_s=900.0, interval_s=15.0):
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = cf.get_distribution(Id=dist_id)
        if resp["Distribution"]["Status"] == "Deployed":
            return resp["ETag"]
        time.sleep(interval_s)
    return None


def _cleanup_distribution(ctx, dist_id):
    cf = ctx.client("cloudfront")
    try:
        cfg_resp = cf.get_distribution_config(Id=dist_id)
        cfg = cfg_resp["DistributionConfig"]
        if cfg.get("Enabled"):
            cfg["Enabled"] = False
            cf.update_distribution(Id=dist_id, IfMatch=cfg_resp["ETag"], DistributionConfig=cfg)
        etag = _wait_distribution_deployed(ctx, dist_id, timeout_s=900.0)
        if etag is None:
            etag = cf.get_distribution(Id=dist_id)["ETag"]
        cf.delete_distribution(Id=dist_id, IfMatch=etag)
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
