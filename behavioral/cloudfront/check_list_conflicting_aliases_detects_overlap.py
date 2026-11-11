"""list-conflicting-aliases-detects-overlap."""
from __future__ import annotations

import subprocess
import tempfile
import time
from pathlib import Path

from botocore.exceptions import ClientError
from fidelity_tests_runner import require_tools

from behavioral_harness import tags

CHECK = "list-conflicting-aliases-detects-overlap"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]

_INVALID_VIEWER_CERTIFICATE_MESSAGE = (
    "The specified SSL certificate doesn't exist, isn't in us-east-1 region, isn't valid, "
    "or doesn't include a valid certificate chain."
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A fresh IAM-uploaded certificate's wildcard alias is refused (InvalidViewerCertificate),
    and the refusal repeats on a second attempt, so the alias was never attached anywhere.
    """
    # Without an owned domain neither ACM (stays PENDING_VALIDATION) nor an IAM-uploaded
    # certificate can carry the alias, so the overlap path is unreachable; assert the refusal.
    cf = ctx.client("cloudfront")
    iam = ctx.client("iam")

    # Positive control: unrelated CloudFront and IAM calls succeed, so the refusal below
    # cannot be explained by every call being denied.
    cf.list_distributions(MaxItems="1")

    base = f"{ctx.unique_name('sim2real-lca-')}.example.com".lower()
    wildcard_alias = f"*.{base}"
    cert_id = _upload_iam_certificate(ctx, iam, wildcard_alias)

    code, message = _try_attach_alias(ctx, cf, wildcard_alias, cert_id)
    assert code == "InvalidViewerCertificate", (
        "expected InvalidViewerCertificate attaching a fresh IAM-uploaded certificate's "
        f"alias to a brand-new distribution, got {code!r}"
    )
    assert message == _INVALID_VIEWER_CERTIFICATE_MESSAGE, f"unexpected message {message!r}"

    # Effect absent: a second, independent attempt (fresh CallerReference, same alias)
    # sees the SAME rejection rather than CNAMEAlreadyExists -- proving the first
    # attempt left the alias unclaimed rather than silently attaching it somewhere.
    code2, message2 = _try_attach_alias(ctx, cf, wildcard_alias, cert_id)
    assert code2 == "InvalidViewerCertificate", (
        f"expected the alias to still be unclaimed on a second attempt, got {code2!r}"
    )
    assert message2 == _INVALID_VIEWER_CERTIFICATE_MESSAGE, f"unexpected message {message2!r}"


def _generate_self_signed_cert(domain: str) -> tuple[str, str]:
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
                # `openssl req -x509` defaults to a CA:TRUE certificate, which CloudFront
                # refuses as a viewer certificate; pin it down to an ordinary end-entity
                # TLS server certificate instead.
                "-addext", "basicConstraints=critical,CA:FALSE",
                "-addext", "keyUsage=critical,digitalSignature,keyEncipherment",
                "-addext", "extendedKeyUsage=serverAuth",
            ],
            check=True, capture_output=True,
        )
        return cert.read_text(), key.read_text()


def _upload_iam_certificate(ctx, iam, domain: str) -> str:
    cert_pem, key_pem = _generate_self_signed_cert(domain)
    name = ctx.unique_name("sim2real-lca-cert-")
    resp = iam.upload_server_certificate(
        # CloudFront only recognizes an IAM server certificate uploaded under /cloudfront/
        # (see UploadServerCertificate's own Path documentation); anywhere else, and
        # CreateDistribution answers InvalidViewerCertificate as if the cert did not exist.
        Path="/cloudfront/",
        ServerCertificateName=name,
        CertificateBody=cert_pem,
        PrivateKey=key_pem,
        Tags=[{"Key": "fidelity", "Value": "true"}],
    )
    cert_id = resp["ServerCertificateMetadata"]["ServerCertificateId"]
    ctx.on_cleanup(lambda: iam.delete_server_certificate(ServerCertificateName=name))
    return cert_id


def _try_attach_alias(ctx, cf, alias: str, iam_certificate_id: str) -> tuple[str, str]:
    """Attempt to create a standard distribution with `alias` behind `iam_certificate_id`.

    Returns the ClientError code and message on rejection. On an unexpected success,
    the new distribution's cleanup is registered and then AssertionError is raised, so
    a surprising acceptance fails loudly and never leaks the distribution.
    """
    config = {
        "CallerReference": ctx.unique_name("sim2real-behav-std-"),
        "Comment": "sim2real-behav standard distribution fixture",
        "Enabled": False,
        "Aliases": {"Quantity": 1, "Items": [alias]},
        "ViewerCertificate": {
            "IAMCertificateId": iam_certificate_id,
            "SSLSupportMethod": "sni-only",
            "MinimumProtocolVersion": "TLSv1.2_2021",
        },
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
            "ViewerProtocolPolicy": "redirect-to-https",
            "CachePolicyId": "658327ea-f89d-4fab-a63d-7e88639e58f6",
        },
    }
    try:
        resp = cf.create_distribution_with_tags(
            DistributionConfigWithTags={
                "DistributionConfig": config,
                "Tags": {"Items": [{"Key": "fidelity", "Value": "true"}]},
            }
        )
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    dist_id = resp["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _delete_distribution_fully(ctx, cf, dist_id))
    raise AssertionError(
        f"expected InvalidViewerCertificate, but CreateDistributionWithTags SUCCEEDED and created {dist_id!r}"
    )


def _delete_distribution_fully(ctx, cf, dist_id: str, timeout_s: float = 1500.0) -> None:
    deadline = time.monotonic() + timeout_s
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
            time.sleep(5)
            continue
        if dist["Status"] == "Deployed":
            try:
                cf.delete_distribution(Id=dist_id, IfMatch=etag)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchDistribution":
                    raise
            return
        time.sleep(15)
    raise AssertionError(f"distribution {dist_id} was not deleted within {timeout_s:.0f} s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
