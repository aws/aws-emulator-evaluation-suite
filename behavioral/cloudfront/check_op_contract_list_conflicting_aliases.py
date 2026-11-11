"""op-contract-listConflictingAliases."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-listConflictingAliases"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListConflictingAliases answers an unknown DistributionId with NoSuchDistribution, and an alias no certificate
    of the distribution covers with InvalidArgument, each with its exact message: conflicts can only be listed for
    an alias the caller has proven control of."""
    cf = ctx.client("cloudfront")
    dist_id = _create_minimal_distribution(ctx)

    alias = f"{ctx.unique_name('sim2real-alias-')}.example.com".lower().replace("_", "-")

    # Boundary 1: a well-formed DistributionId (E plus 12 uppercase alphanumerics) that names no distribution;
    # a malformed ID is refused for its format before the lookup.
    code, msg = _error(
        lambda: cf.list_conflicting_aliases(DistributionId="EDFAKE0000001", Alias=alias)
    )
    assert code == "NoSuchDistribution", f"expected NoSuchDistribution, got {code}"
    assert msg == "The specified distribution does not exist.", f"unexpected NoSuchDistribution message: {msg!r}"

    # Boundary 2: a valid alias that no certificate covers is refused with InvalidArgument,
    # not answered with an empty conflicts list.
    code, msg = _error(lambda: cf.list_conflicting_aliases(DistributionId=dist_id, Alias=alias))
    assert code == "InvalidArgument", f"expected InvalidArgument, got {code}"
    assert msg == "The parameter CNAME contains one or more parameters that are not valid.", f"unexpected InvalidArgument message: {msg!r}"


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. A call that
    succeeds raises AssertionError: accepting input AWS refuses must fail loudly, not read
    as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _create_minimal_distribution(ctx) -> str:
    cf = ctx.client("cloudfront")
    ref = ctx.unique_name("sim2real-dist-")
    config = {
        "CallerReference": ref,
        "Comment": "sim2real behavioral check",
        "Enabled": True,
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": "primary-origin",
                    "DomainName": f"{ctx.unique_name('sim2real-distbkt-')}.s3.amazonaws.com",
                    "S3OriginConfig": {"OriginAccessIdentity": ""},
                }
            ],
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": "primary-origin",
            "ViewerProtocolPolicy": "allow-all",
            "TrustedSigners": {"Enabled": False, "Quantity": 0},
            "ForwardedValues": {
                "QueryString": False,
                "Cookies": {"Forward": "none"},
            },
            "MinTTL": 0,
        },
    }
    created = cf.create_distribution_with_tags(
        DistributionConfigWithTags={
            "DistributionConfig": config,
            "Tags": {"Items": [{"Key": "sim2real:managed", "Value": "true"}]},
        }
    )
    dist_id = created["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _cleanup_distribution(cf, dist_id))
    return dist_id


def _cleanup_distribution(cf, dist_id):
    try:
        cur = cf.get_distribution_config(Id=dist_id)
        cfg = cur["DistributionConfig"]
        etag = cur["ETag"]
        if cfg.get("Enabled"):
            cfg["Enabled"] = False
            updated = cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=cfg)
            etag = updated["ETag"]
        deadline = time.monotonic() + 900
        while time.monotonic() < deadline:
            desc = cf.get_distribution(Id=dist_id)
            if desc["Distribution"]["Status"] == "Deployed":
                cf.delete_distribution(Id=dist_id, IfMatch=desc["ETag"])
                return
            time.sleep(15)
        raise AssertionError(f"distribution {dist_id} did not reach Deployed within 900 s to be deleted")
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
