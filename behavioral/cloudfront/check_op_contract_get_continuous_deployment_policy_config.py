"""op-contract-get-continuous-deployment-policy-config."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-get-continuous-deployment-policy-config"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetContinuousDeploymentPolicyConfig returns Enabled and the staging distribution's domain name as stored.

    An unknown Id and the deleted policy's Id both fail with NoSuchContinuousDeploymentPolicy and its exact message.
    """
    # One teardown deadline per run, started by the first teardown that runs.
    teardown_deadline: dict = {}
    cf = ctx.client("cloudfront")
    primary_id, primary_etag = _create_minimal_distribution(ctx, teardown_deadline)

    copy_resp = cf.copy_distribution(
        PrimaryDistributionId=primary_id,
        IfMatch=primary_etag,
        Staging=True,
        CallerReference=ctx.unique_name("sim2real-behav-cdpcfg-stg-"),
        Enabled=True,
    )
    staging_id = copy_resp["Distribution"]["Id"]
    staging_dns = copy_resp["Distribution"]["DomainName"]
    ctx.on_cleanup(lambda: _delete_distribution(ctx, staging_id, teardown_deadline))

    config = {
        "Enabled": True,
        "StagingDistributionDnsNames": {"Quantity": 1, "Items": [staging_dns]},
        "TrafficConfig": {
            "Type": "SingleWeight",
            "SingleWeightConfig": {"Weight": 0.15},
        },
    }
    created = cf.create_continuous_deployment_policy(ContinuousDeploymentPolicyConfig=config)
    policy_id = created["ContinuousDeploymentPolicy"]["Id"]

    def _cleanup() -> None:
        try:
            cur = cf.get_continuous_deployment_policy(Id=policy_id)
            cf.delete_continuous_deployment_policy(Id=policy_id, IfMatch=cur["ETag"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchContinuousDeploymentPolicy":
                raise

    ctx.on_cleanup(_cleanup)

    # success-path contract
    got = cf.get_continuous_deployment_policy_config(Id=policy_id)
    cfg = got["ContinuousDeploymentPolicyConfig"]
    assert cfg["Enabled"] is True, f"expected Enabled True, got {cfg.get('Enabled')!r}"
    assert cfg["StagingDistributionDnsNames"]["Items"] == [staging_dns], (
        f"expected StagingDistributionDnsNames.Items == [{staging_dns!r}], "
        f"got {cfg['StagingDistributionDnsNames']['Items']!r}"
    )
    assert "ETag" in got, f"expected an ETag in the response, got keys {sorted(got)!r}"

    # distinct error boundary: unknown Id
    not_found_message = "The specified continuous deployment policy does not exist."
    code, message = _error(lambda: cf.get_continuous_deployment_policy_config(Id="AABBCCDDEEFF01"))
    assert code == "NoSuchContinuousDeploymentPolicy", f"unexpected code {code}"
    assert message == not_found_message, f"expected message {not_found_message!r}, got {message!r}"

    # Delete the policy, then read it back: the deleted Id answers not-found. DeletePolicy can answer
    # PreconditionFailed while the staging distribution is still deploying to edge locations, so it is retried.
    _delete_policy_with_retry(cf, policy_id)
    gone_code, gone_message = _error(lambda: cf.get_continuous_deployment_policy_config(Id=policy_id))
    assert gone_code == "NoSuchContinuousDeploymentPolicy", (
        f"expected NoSuchContinuousDeploymentPolicy after delete, got {gone_code}"
    )
    assert gone_message == not_found_message, f"expected message {not_found_message!r}, got {gone_message!r}"


def _delete_policy_with_retry(cf, policy_id: str, timeout_s: float = 600.0, interval_s: float = 20.0) -> None:
    """DeleteContinuousDeploymentPolicy with a fresh ETag, retried on PreconditionFailed while the staging
    distribution is still deploying to edge locations."""
    deadline = time.monotonic() + timeout_s
    while True:
        etag = cf.get_continuous_deployment_policy(Id=policy_id)["ETag"]
        try:
            cf.delete_continuous_deployment_policy(Id=policy_id, IfMatch=etag)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "PreconditionFailed" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore (code, message). A success raises: accepting a call AWS refuses is a
    finding in itself, not an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _create_minimal_distribution(ctx, teardown_deadline):
    cf = ctx.client("cloudfront")
    caller_ref = ctx.unique_name("sim2real-behav-dist-")
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
    dist_id = resp["Distribution"]["Id"]
    etag = resp["ETag"]
    ctx.on_cleanup(lambda: _delete_distribution(ctx, dist_id, teardown_deadline))
    return dist_id, etag


# budget.cleanup_timeout for behavioral/cloudfront, one deadline shared by both distribution teardowns.
_TEARDOWN_RETRY_S = 1800.0


def _delete_distribution(ctx, dist_id, teardown_deadline):
    cf = ctx.client("cloudfront")
    deadline = teardown_deadline.setdefault("t", time.monotonic() + _TEARDOWN_RETRY_S - 120.0)
    try:
        while time.monotonic() < deadline:
            resp = cf.get_distribution(Id=dist_id)
            dist = resp["Distribution"]
            if dist["Status"] == "Deployed":
                config = dist["DistributionConfig"]
                if config.get("Enabled"):
                    # Distributions must be disabled before they can be deleted;
                    # flip it off and let the loop re-poll until Deployed again.
                    config["Enabled"] = False
                    cf.update_distribution(
                        Id=dist_id, IfMatch=resp["ETag"], DistributionConfig=config
                    )
                    time.sleep(15)
                    continue
                cf.delete_distribution(Id=dist_id, IfMatch=resp["ETag"])
                return
            time.sleep(15)
        raise AssertionError(f"distribution {dist_id} was not deleted before the teardown deadline")
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
