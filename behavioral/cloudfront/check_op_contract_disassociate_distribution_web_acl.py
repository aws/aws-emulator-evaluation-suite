"""op-contract-disassociateDistributionWebACL."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-disassociateDistributionWebACL"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DisassociateDistributionWebACL: succeeds (idempotently) on a
    distribution that never had a WebACL, returning a fresh ETag, and
    rejects a stale/incorrect IfMatch (PreconditionFailed)."""
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-dwacl-")
    created = cf.create_distribution(
        DistributionConfig={
            "CallerReference": name,
            "Comment": "sim2real behavioral check",
            "Enabled": True,
            "Origins": {
                "Quantity": 1,
                "Items": [
                    {
                        "Id": "origin1",
                        "DomainName": f"{name}.example.com",
                        "CustomOriginConfig": {
                            "HTTPPort": 80,
                            "HTTPSPort": 443,
                            "OriginProtocolPolicy": "https-only",
                        },
                    }
                ],
            },
            "DefaultCacheBehavior": {
                "TargetOriginId": "origin1",
                "ViewerProtocolPolicy": "allow-all",
                "CachePolicyId": "658327ea-f89d-4fab-a63d-7e88639e58f6",
            },
        }
    )
    dist_id = created["Distribution"]["Id"]
    etag = created["ETag"]
    created_web_acl_id = created["Distribution"]["DistributionConfig"].get("WebACLId", "")
    assert created_web_acl_id == "", f"expected no WebACLId on creation, got {created_web_acl_id!r}"
    ctx.on_cleanup(lambda: _safe_teardown(cf, dist_id))

    # success path: disassociating when nothing was associated is a legal no-op
    result = cf.disassociate_distribution_web_acl(Id=dist_id, IfMatch=etag)
    assert result["Id"] == dist_id, f"expected Id {dist_id!r} in response, got {result.get('Id')!r}"
    assert "ETag" in result, f"expected an ETag in the disassociate response, got keys {sorted(result)}"

    # distinct error boundary: a clearly wrong IfMatch is rejected. Real
    # CloudFront reports this as InvalidIfMatchVersion (not the generic
    # PreconditionFailed) for a malformed/stale ETag value.
    code, msg = _error(
        lambda: cf.disassociate_distribution_web_acl(Id=dist_id, IfMatch="E000000000FAKEBOGUS")
    )
    assert code == "InvalidIfMatchVersion", f"expected InvalidIfMatchVersion, got {code}"
    assert msg == "The If-Match version is missing or not valid for the resource.", f"unexpected InvalidIfMatchVersion message: {msg!r}"

    final_cfg = cf.get_distribution_config(Id=dist_id)["DistributionConfig"]
    final_web_acl_id = final_cfg.get("WebACLId", "")
    assert final_web_acl_id == "", f"expected WebACLId to remain empty, got {final_web_acl_id!r}"


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. A call that
    succeeds raises AssertionError: an emulator accepting input real AWS refuses must fail
    loudly, not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _safe_teardown(cf, dist_id: str) -> None:
    try:
        current = cf.get_distribution_config(Id=dist_id)
        cfg = current["DistributionConfig"]
        if cfg.get("Enabled"):
            cfg["Enabled"] = False
            cf.update_distribution(Id=dist_id, IfMatch=current["ETag"], DistributionConfig=cfg)
        deadline = time.monotonic() + 900.0
        while time.monotonic() < deadline:
            got = cf.get_distribution(Id=dist_id)
            if got["Distribution"]["Status"] == "Deployed":
                cf.delete_distribution(Id=dist_id, IfMatch=got["ETag"])
                return
            time.sleep(20)
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
