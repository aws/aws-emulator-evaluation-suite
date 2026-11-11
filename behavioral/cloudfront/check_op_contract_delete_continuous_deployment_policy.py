"""op-contract-deleteContinuousDeploymentPolicy."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deleteContinuousDeploymentPolicy"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteContinuousDeploymentPolicy rejects a never-existing Id and a stale ETag with
    InvalidIfMatchVersion, deletes with the correct ETag (then Get is NotFound), and re-deleting the
    deleted Id fails NoSuchContinuousDeploymentPolicy, distinct from the never-existed case.
    """
    cf = ctx.client("cloudfront")

    # StagingDistributionDnsNames must name a REAL, enabled staging distribution; a fabricated
    # domain is rejected with InvalidArgument.
    primary_id, primary_etag = _create_minimal_distribution(ctx)
    ctx.on_cleanup(lambda: _delete_distribution_best_effort(ctx, primary_id))

    copy_resp = cf.copy_distribution(
        PrimaryDistributionId=primary_id,
        IfMatch=primary_etag,
        Staging=True,
        CallerReference=ctx.unique_name("sim2real-behav-cdp-del-stg-"),
        Enabled=True,
    )
    staging_id = copy_resp["Distribution"]["Id"]
    staging_dns = copy_resp["Distribution"]["DomainName"]
    ctx.on_cleanup(lambda: _delete_distribution_best_effort(ctx, staging_id))

    created = cf.create_continuous_deployment_policy(
        ContinuousDeploymentPolicyConfig={
            "Enabled": False,
            "StagingDistributionDnsNames": {"Quantity": 1, "Items": [staging_dns]},
            "TrafficConfig": {
                "Type": "SingleWeight",
                "SingleWeightConfig": {"Weight": 0.1},
            },
        }
    )

    policy_id = created["ContinuousDeploymentPolicy"]["Id"]
    etag = created["ETag"]

    def _cleanup(policy_id=policy_id):
        try:
            fresh = cf.get_continuous_deployment_policy(Id=policy_id)
            _delete_policy_with_retry(cf, policy_id, fresh["ETag"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchContinuousDeploymentPolicy":
                raise

    ctx.on_cleanup(_cleanup)

    # positive control: the freshly created policy is independently fetchable before we
    # start exercising delete's error semantics against it
    fetched = cf.get_continuous_deployment_policy(Id=policy_id)
    fetched_dns = fetched["ContinuousDeploymentPolicy"]["ContinuousDeploymentPolicyConfig"][
        "StagingDistributionDnsNames"
    ]["Items"]
    assert fetched_dns == [staging_dns], f"expected staging dns {[staging_dns]}, got {fetched_dns}"

    # error boundary #1 (always-invalid, no restore leg by construction): a wholly unknown
    # Id is rejected before CloudFront ever gets to check whether it exists
    unknown_code, unknown_message = _error(
        lambda: cf.delete_continuous_deployment_policy(Id="sim2real-nonexistent-cdp-id")
    )
    assert unknown_code == "InvalidIfMatchVersion", (
        f"expected InvalidIfMatchVersion for an unknown Id, got {unknown_code}"
    )
    assert unknown_message == "The If-Match version is missing or not valid for the resource.", (
        f"expected the exact refusal message, got {unknown_message!r}"
    )

    # error boundary #2 (broken-then-restored): a stale ETag on the REAL policy is rejected
    # the same way, the policy is untouched (independent read still finds it), and the
    # identical call with the correct ETag then succeeds
    stale_code, stale_message = _error(
        lambda: cf.delete_continuous_deployment_policy(Id=policy_id, IfMatch="E000000000000A")
    )
    assert stale_code == "InvalidIfMatchVersion", (
        f"expected InvalidIfMatchVersion for a stale ETag, got {stale_code}"
    )
    assert stale_message == "The If-Match version is missing or not valid for the resource.", (
        f"expected the exact refusal message, got {stale_message!r}"
    )
    still_there = cf.get_continuous_deployment_policy(Id=policy_id)
    still_there_id = still_there["ContinuousDeploymentPolicy"]["Id"]
    assert still_there_id == policy_id, (
        f"expected the rejected delete to leave {policy_id} in place, got {still_there_id}"
    )

    # restore + success path: the correct ETag deletes it. CloudFront can reject this with
    # PreconditionFailed ("recent changes made to the staging distribution are not fully
    # deployed to the edge locations") while the staging distribution enabled above is
    # still propagating -- a bounded retry, not a fixed sleep, since propagation time varies.
    _delete_policy_with_retry(cf, policy_id, etag)
    gone_code, gone_message = _error(lambda: cf.get_continuous_deployment_policy(Id=policy_id))
    assert gone_code == "NoSuchContinuousDeploymentPolicy", (
        f"expected NoSuchContinuousDeploymentPolicy after delete, got {gone_code}"
    )
    assert gone_message == "The specified continuous deployment policy does not exist.", (
        f"expected the exact refusal message, got {gone_message!r}"
    )

    # a mutation against the now-dead id: unlike a NEVER-existed Id (InvalidIfMatchVersion
    # above), an Id that existed and was deleted keeps a distinct identity -- re-deleting it
    # is NoSuchContinuousDeploymentPolicy even with the once-valid ETag
    redelete_code, redelete_message = _error(
        lambda: cf.delete_continuous_deployment_policy(Id=policy_id, IfMatch=etag)
    )
    assert redelete_code == "NoSuchContinuousDeploymentPolicy", (
        f"expected NoSuchContinuousDeploymentPolicy re-deleting an already-deleted policy, got {redelete_code}"
    )
    assert redelete_message == "The specified continuous deployment policy does not exist.", (
        f"expected the exact refusal message, got {redelete_message!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises,
    so a call AWS refuses is never read as a mere code mismatch.
    """
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _delete_policy_with_retry(cf, policy_id: str, etag: str, timeout_s: float = 900.0, interval_s: float = 20.0) -> None:
    """DeleteContinuousDeploymentPolicy, retrying on PreconditionFailed while the staging
    distribution it references is still propagating to the edge. Bounded, not a blind sleep."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            cf.delete_continuous_deployment_policy(Id=policy_id, IfMatch=etag)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "PreconditionFailed" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _create_minimal_distribution(ctx):
    cf = ctx.client("cloudfront")
    caller_ref = ctx.unique_name("sim2real-behav-cdp-del-primary-")
    config = {
        "CallerReference": caller_ref,
        "Comment": caller_ref,
        "Enabled": False,
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": "primary-origin",
                    "DomainName": "example.com",
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
            "CachePolicyId": "658327ea-f89d-4fab-a63d-7e88639e58f6",  # CachingOptimized
        },
    }
    resp = cf.create_distribution(DistributionConfig=config)
    return resp["Distribution"]["Id"], resp["ETag"]


def _delete_distribution_best_effort(ctx, dist_id):
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + 900.0
    try:
        while time.monotonic() < deadline:
            resp = cf.get_distribution(Id=dist_id)
            dist = resp["Distribution"]
            if dist["Status"] == "Deployed":
                config = dist["DistributionConfig"]
                if config.get("Enabled"):
                    config["Enabled"] = False
                    cf.update_distribution(
                        Id=dist_id, IfMatch=resp["ETag"], DistributionConfig=config
                    )
                    time.sleep(15)
                    continue
                cf.delete_distribution(Id=dist_id, IfMatch=resp["ETag"])
                return
            time.sleep(15)
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
