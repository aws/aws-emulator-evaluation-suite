"""create-continuous-deployment-policy-disabled-staging-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-continuous-deployment-policy-disabled-staging-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]

_MANAGED_CACHING_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"


def _wait_deployed(cf, dist_id, *, timeout_s=900.0, interval_s=10.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if cf.get_distribution(Id=dist_id)["Distribution"]["Status"] == "Deployed":
            return
        time.sleep(interval_s)
    raise AssertionError(f"distribution {dist_id} never reached Deployed within {timeout_s}s")


def _disable_and_delete_distribution(cf, dist_id) -> None:
    cfg_resp = cf.get_distribution_config(Id=dist_id)
    cfg = cfg_resp["DistributionConfig"]
    etag = cfg_resp["ETag"]
    if cfg.get("Enabled"):
        cfg["Enabled"] = False
        etag = cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=cfg)["ETag"]
    _wait_deployed(cf, dist_id)
    etag = cf.get_distribution(Id=dist_id)["ETag"]
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


def _delete_policy_with_etag(cf, policy_id) -> None:
    etag = cf.get_continuous_deployment_policy(Id=policy_id)["ETag"]
    cf.delete_continuous_deployment_policy(Id=policy_id, IfMatch=etag)


def _create_distribution(ctx, comment: str, *, enabled: bool) -> tuple[str, str]:
    """A minimal distribution over a placeholder custom origin; never fetched."""
    cf = ctx.client("cloudfront")
    resp = cf.create_distribution(DistributionConfig={
        "CallerReference": ctx.unique_name("sim2real-cfcdp-neg-"),
        "Comment": comment,
        "Enabled": enabled,
        "Origins": {"Quantity": 1, "Items": [{
            "Id": "placeholder-origin",
            "DomainName": "example.com",
            "CustomOriginConfig": {
                "HTTPPort": 80,
                "HTTPSPort": 443,
                "OriginProtocolPolicy": "https-only",
                "OriginSslProtocols": {"Quantity": 1, "Items": ["TLSv1.2"]},
            },
        }]},
        "DefaultCacheBehavior": {
            "TargetOriginId": "placeholder-origin",
            "ViewerProtocolPolicy": "redirect-to-https",
            "CachePolicyId": _MANAGED_CACHING_OPTIMIZED,
        },
    })
    return resp["Distribution"]["Id"], resp["ETag"]


def _weight_policy_config(staging_dns: str) -> dict:
    return {
        "StagingDistributionDnsNames": {"Quantity": 1, "Items": [staging_dns]},
        "Enabled": True,
        "TrafficConfig": {
            "Type": "SingleWeight",
            "SingleWeightConfig": {"Weight": 0.1},
        },
    }


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateContinuousDeploymentPolicy refuses a staging distribution that is itself Disabled,
    and succeeds once that same distribution is enabled, with no phantom policy left behind.
    """
    cf = ctx.client("cloudfront")

    primary_id, primary_etag = _create_distribution(ctx, "sim2real continuous deployment negative primary",
                                                     enabled=False)
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(cf, primary_id))

    staging = cf.copy_distribution(
        PrimaryDistributionId=primary_id, IfMatch=primary_etag, Staging=True, Enabled=False,
        CallerReference=ctx.unique_name("sim2real-cfcdp-neg-stag-"),
    )["Distribution"]
    staging_id = staging["Id"]
    staging_dns = staging["DomainName"]
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(cf, staging_id))
    _wait_deployed(cf, staging_id)

    try:
        result = cf.create_continuous_deployment_policy(
            ContinuousDeploymentPolicyConfig=_weight_policy_config(staging_dns)
        )
    except ClientError as exc:
        err = exc.response["Error"]
        code, message = err["Code"], err["Message"]
    else:
        raise AssertionError(
            f"creating a policy over a disabled staging distribution succeeded: {result!r}"
        )
    assert code == "InvalidArgument", f"expected InvalidArgument, got {code!r}: {message!r}"
    expected_message = "The parameter Staging distributions contains disabled distributions."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    listed = cf.list_continuous_deployment_policies()
    referencing = [
        item["ContinuousDeploymentPolicy"]["Id"]
        for item in listed.get("ContinuousDeploymentPolicyList", {}).get("Items", [])
        if item["ContinuousDeploymentPolicy"]["ContinuousDeploymentPolicyConfig"][
            "StagingDistributionDnsNames"
        ]["Items"] == [staging_dns]
    ]
    assert referencing == [], f"a rejected create left a phantom policy: {referencing!r}"

    staging_cfg_resp = cf.get_distribution_config(Id=staging_id)
    staging_cfg = staging_cfg_resp["DistributionConfig"]
    staging_cfg["Enabled"] = True
    cf.update_distribution(Id=staging_id, IfMatch=staging_cfg_resp["ETag"], DistributionConfig=staging_cfg)
    _wait_deployed(cf, staging_id)

    enabled_result = cf.create_continuous_deployment_policy(
        ContinuousDeploymentPolicyConfig=_weight_policy_config(staging_dns)
    )["ContinuousDeploymentPolicy"]
    policy_id = enabled_result["Id"]
    ctx.on_cleanup(lambda: _delete_policy_with_etag(cf, policy_id))
    created_dns = enabled_result["ContinuousDeploymentPolicyConfig"]["StagingDistributionDnsNames"]["Items"]
    assert created_dns == [staging_dns], (
        f"the identical call, now over an enabled staging distribution, recorded {created_dns!r}"
    )

    reread = cf.get_continuous_deployment_policy(Id=policy_id)["ContinuousDeploymentPolicy"]
    reread_dns = reread["ContinuousDeploymentPolicyConfig"]["StagingDistributionDnsNames"]["Items"]
    assert reread_dns == [staging_dns], (
        f"an independent read of the created policy showed {reread_dns!r}, not {[staging_dns]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
