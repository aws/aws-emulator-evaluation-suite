"""op-contract-create-continuous-deployment-policy."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-create-continuous-deployment-policy"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateContinuousDeploymentPolicy round-trips its config; reusing a claimed staging DNS name
    fails with StagingDistributionInUse, leaves no phantom policy, and succeeds once the first
    policy is deleted.
    """
    cf = ctx.client("cloudfront")
    # The DNS name must belong to a real, enabled staging distribution (InvalidArgument otherwise).
    # The block depends only on another policy referencing the name, so no primary is attached.
    primary_id, primary_etag = _create_minimal_distribution(ctx)

    copy_resp = cf.copy_distribution(
        PrimaryDistributionId=primary_id,
        IfMatch=primary_etag,
        Staging=True,
        CallerReference=ctx.unique_name("sim2real-behav-cdp-stg-"),
        Enabled=True,
    )
    staging_id = copy_resp["Distribution"]["Id"]
    staging_dns = copy_resp["Distribution"]["DomainName"]
    ctx.on_cleanup(lambda: _delete_distribution_best_effort(ctx, staging_id))

    config = _policy_config(staging_dns, weight=0.15)

    resp = cf.create_continuous_deployment_policy(ContinuousDeploymentPolicyConfig=config)
    policy_id = resp["ContinuousDeploymentPolicy"]["Id"]
    etag = resp["ETag"]
    ctx.on_cleanup(lambda: _delete_policy_best_effort(cf, policy_id, etag))

    returned = resp["ContinuousDeploymentPolicy"]["ContinuousDeploymentPolicyConfig"]
    assert returned["Enabled"] is True
    assert returned["StagingDistributionDnsNames"]["Items"] == [staging_dns]
    assert returned["TrafficConfig"]["Type"] == "SingleWeight"
    assert returned["TrafficConfig"]["SingleWeightConfig"]["Weight"] == 0.15

    # Weight must stay within [0, 0.15], or InvalidArgument preempts StagingDistributionInUse.
    code, message = _error(
        lambda: cf.create_continuous_deployment_policy(
            ContinuousDeploymentPolicyConfig=_policy_config(staging_dns, weight=0.1)
        )
    )
    assert code == "StagingDistributionInUse", f"expected StagingDistributionInUse, got {code}"
    expected = "One or more staging distributions are associated with another continuous deployment policy in your account."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # An independent List shows the rejected create left no phantom policy.
    listed = cf.list_continuous_deployment_policies()
    matching_ids = [
        item["ContinuousDeploymentPolicy"]["Id"]
        for item in listed.get("ContinuousDeploymentPolicyList", {}).get("Items", [])
        if item["ContinuousDeploymentPolicy"]["ContinuousDeploymentPolicyConfig"][
            "StagingDistributionDnsNames"
        ]["Items"]
        == [staging_dns]
    ]
    assert matching_ids == [policy_id], (
        f"expected only {policy_id!r} referencing {staging_dns!r}, found {matching_ids!r}"
    )

    # Delete fails with PreconditionFailed until the staging distribution reaches Deployed.
    _wait_for_deployed(cf, staging_id)
    _delete_policy_with_retry(cf, policy_id, etag)

    gone_code, gone_message = _error(lambda: cf.get_continuous_deployment_policy(Id=policy_id))
    assert gone_code == "NoSuchContinuousDeploymentPolicy", (
        f"expected NoSuchContinuousDeploymentPolicy after delete, got {gone_code}"
    )
    expected = "The specified continuous deployment policy does not exist."
    assert gone_message == expected, f"expected message {expected!r}, got {gone_message!r}"

    restored_resp = cf.create_continuous_deployment_policy(
        ContinuousDeploymentPolicyConfig=_policy_config(staging_dns, weight=0.1)
    )
    restored_id = restored_resp["ContinuousDeploymentPolicy"]["Id"]
    restored_etag = restored_resp["ETag"]
    ctx.on_cleanup(lambda: _delete_policy_best_effort(cf, restored_id, restored_etag))
    restored_config = restored_resp["ContinuousDeploymentPolicy"]["ContinuousDeploymentPolicyConfig"]
    assert restored_config["StagingDistributionDnsNames"]["Items"] == [staging_dns], (
        "expected the restored create to succeed once the original policy was deleted"
    )

    reread = cf.get_continuous_deployment_policy(Id=restored_id)
    reread_config = reread["ContinuousDeploymentPolicy"]["ContinuousDeploymentPolicyConfig"]
    assert reread_config["StagingDistributionDnsNames"]["Items"] == [staging_dns], (
        f"expected an independent read of {restored_id!r} to show {staging_dns!r}, "
        f"got {reread_config['StagingDistributionDnsNames']['Items']!r}"
    )


def _policy_config(staging_dns, weight):
    return {
        "Enabled": True,
        "StagingDistributionDnsNames": {"Quantity": 1, "Items": [staging_dns]},
        "TrafficConfig": {
            "Type": "SingleWeight",
            "SingleWeightConfig": {"Weight": weight},
        },
    }


def _create_minimal_distribution(ctx):
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
    ctx.on_cleanup(lambda: _delete_distribution_best_effort(ctx, dist_id))
    return dist_id, etag


def _wait_for_deployed(cf, dist_id, timeout=900.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        resp = cf.get_distribution(Id=dist_id)
        if resp["Distribution"]["Status"] == "Deployed":
            return
        time.sleep(2)
    raise TimeoutError(f"distribution {dist_id} did not reach Deployed within {timeout}s")


def _delete_policy_with_retry(cf, policy_id, etag, timeout=60.0):
    """Delete a continuous deployment policy, re-fetching the ETag and retrying on
    PreconditionFailed while the policy settles."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout
    while True:
        try:
            cf.delete_continuous_deployment_policy(Id=policy_id, IfMatch=etag)
            return
        except ClientError as exc:
            if (
                exc.response.get("Error", {}).get("Code") != "PreconditionFailed"
                or time.monotonic() >= deadline
            ):
                raise
            etag = cf.get_continuous_deployment_policy_config(Id=policy_id)["ETag"]
            time.sleep(2)


def _delete_policy_best_effort(cf, policy_id, etag):
    try:
        _delete_policy_with_retry(cf, policy_id, etag)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchContinuousDeploymentPolicy":
            raise


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


def _error(fn):
    """Call fn(); return the ClientError (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
