"""list-domain-conflicts-detects-collision."""
from __future__ import annotations

import subprocess
import tempfile
import time
from pathlib import Path

from behavioral_harness import tags
from fidelity_tests_runner import require_tools
from botocore.exceptions import ClientError

CHECK = "list-domain-conflicts-detects-collision"
GROUP = "data-plane"
SERVICES = ["cloudfront"]


def _poll_until(probe, predicate, timeout_s=1800.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never became true within {timeout_s}s (last={last!r})")


def _wait_distribution_deployed(ctx, dist_id, timeout_s=1800.0, interval_s=15.0):
    cf = ctx.client("cloudfront")
    resp = _poll_until(
        lambda: cf.get_distribution(Id=dist_id),
        lambda r: r["Distribution"]["Status"] == "Deployed",
        timeout_s=timeout_s,
        interval_s=interval_s,
    )
    return resp["ETag"]


def _delete_distribution(ctx, dist_id):
    cf = ctx.client("cloudfront")
    _wait_distribution_deployed(ctx, dist_id)
    config_resp = cf.get_distribution_config(Id=dist_id)
    config = config_resp["DistributionConfig"]
    if config.get("Enabled"):
        config["Enabled"] = False
        cf.update_distribution(Id=dist_id, DistributionConfig=config, IfMatch=config_resp["ETag"])
        _wait_distribution_deployed(ctx, dist_id)
    etag = cf.get_distribution(Id=dist_id)["ETag"]
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


def _delete_distribution_tenant(ctx, tenant_id):
    cf = ctx.client("cloudfront")
    try:
        resp = cf.get_distribution_tenant(Identifier=tenant_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFound":
            raise
        return
    cf.delete_distribution_tenant(Id=tenant_id, IfMatch=resp["ETag"])


def _create_multi_tenant_distribution(ctx):
    # Enabled=True is required here: real AWS rejects CreateDistributionTenant with
    # InvalidAssociation ("The specified multi-tenant distribution is disabled") on a
    # disabled parent, even though the tenant itself is created disabled below.
    cf = ctx.client("cloudfront")
    origin_domain = f"{ctx.unique_name('sim2real-cf-origin-')}.s3.us-east-1.amazonaws.com"
    resp = cf.create_distribution_with_tags(
        DistributionConfigWithTags={
            "DistributionConfig": {
                "CallerReference": ctx.unique_name("sim2real-cf-mt-"),
                "Comment": "sim2real behavioral check multi-tenant distribution",
                "Enabled": True,
                "ConnectionMode": "tenant-only",
                "TenantConfig": {
                    "ParameterDefinitions": [
                        {
                            "Name": "tenantName",
                            "Definition": {
                                "StringSchema": {
                                    "Comment": "tenant name",
                                    "DefaultValue": "root",
                                    "Required": False,
                                }
                            },
                        }
                    ]
                },
                "Origins": {
                    "Quantity": 1,
                    "Items": [
                        {
                            "Id": "primary-origin",
                            "DomainName": origin_domain,
                            "OriginPath": "/{{tenantName}}",
                            "S3OriginConfig": {"OriginAccessIdentity": ""},
                        }
                    ],
                },
                "DefaultCacheBehavior": {
                    "TargetOriginId": "primary-origin",
                    "ViewerProtocolPolicy": "allow-all",
                    "CachePolicyId": "658327ea-f89d-4fab-a63d-7e88639e58f6",
                },
            },
            "Tags": {"Items": [{"Key": "sim2real", "Value": CHECK}]},
        }
    )
    dist_id = resp["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _delete_distribution(ctx, dist_id))
    return dist_id


def _create_distribution_tenant(ctx, distribution_id, domain, **extra):
    cf = ctx.client("cloudfront")
    kwargs = {
        "DistributionId": distribution_id,
        "Name": ctx.unique_name("sim2real-cf-tenant-"),
        "Domains": [{"Domain": domain}],
        "Enabled": False,
    }
    kwargs.setdefault("Tags", {"Items": [{"Key": "sim2real", "Value": CHECK}]})
    kwargs.update(extra)
    resp = cf.create_distribution_tenant(**kwargs)
    tenant = resp["DistributionTenant"]
    ctx.on_cleanup(lambda tid=tenant["Id"]: _delete_distribution_tenant(ctx, tid))
    return tenant


def _generate_self_signed_cert(domain):
    """A self-signed cert+key covering `domain` via SAN, generated locally with openssl."""
    require_tools("openssl")
    with tempfile.TemporaryDirectory() as tmp:
        key = Path(tmp) / "key.pem"
        cert = Path(tmp) / "cert.pem"
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(key), "-out", str(cert), "-days", "2",
                "-subj", f"/CN={domain}",
                "-addext", f"subjectAltName=DNS:{domain}",
            ],
            check=True, capture_output=True,
        )
        return cert.read_text(), key.read_text()


def _import_acm_certificate(ctx, domain):
    # Distribution-tenant Customizations.Certificate.Arn requires an ACM certificate
    # specifically (an IAM server certificate ARN is rejected as "not a valid certificate
    # chain") -- ImportCertificate skips domain validation the same way IAM upload does.
    acm = ctx.client("acm")
    cert_pem, key_pem = _generate_self_signed_cert(domain)
    resp = acm.import_certificate(
        Certificate=cert_pem.encode(),
        PrivateKey=key_pem.encode(),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    cert_arn = resp["CertificateArn"]
    ctx.on_cleanup(lambda: acm.delete_certificate(CertificateArn=cert_arn))
    return cert_arn


def _error_code_and_message(fn):
    from botocore.exceptions import ClientError

    try:
        resp = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {resp!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDistributionTenant rejects a domain not proven under DNS control, even with an imported
    self-signed ACM certificate, with InvalidArgument; GetDistributionTenantByDomain confirms no
    tenant exists for that domain."""
    domain = f"{ctx.unique_name('sim2real-cf-domconflict')}.example.com".replace("_", "-")
    cf = ctx.client("cloudfront")

    # Positive control: the parent distribution creates fine, so the rejection below is a
    # domain-validation refusal, not a permissions or setup problem.
    mt_dist_id = _create_multi_tenant_distribution(ctx)

    tenant_cert_arn = _import_acm_certificate(ctx, domain)
    code, message = _error_code_and_message(
        lambda: _create_distribution_tenant(
            ctx, mt_dist_id, domain, Customizations={"Certificate": {"Arn": tenant_cert_arn}}
        )
    )
    assert code == "InvalidArgument", f"expected InvalidArgument, got {code!r} ({message!r})"
    assert message == "The request contains an invalid domain name.", (
        f"expected the invalid-domain refusal, got {message!r}"
    )

    # Effect-absent, via an independent read (a different operation than the rejected
    # CreateDistributionTenant): no tenant was ever created, so the domain resolves to none.
    code, message = _error_code_and_message(lambda: cf.get_distribution_tenant_by_domain(Domain=domain))
    assert code == "EntityNotFound", f"expected EntityNotFound for an unbound domain, got {code!r}"
    assert message == "The specified distribution tenant doesn't exist.", f"unexpected message {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
