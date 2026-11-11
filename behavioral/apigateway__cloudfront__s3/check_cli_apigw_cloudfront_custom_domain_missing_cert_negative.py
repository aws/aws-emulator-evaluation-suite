"""cli-apigw-cloudfront-custom-domain-missing-cert-negative."""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import time

from fidelity_tests_runner import require_tools

from behavioral_harness import tags

CHECK = "cli-apigw-cloudfront-custom-domain-missing-cert-negative"
GROUP = "overly-permissive"
SERVICES = ["apigateway", "cloudfront", "s3"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CloudFront rejects CreateDistribution for an alternate domain name (CNAME) on an API Gateway origin
    with only the default certificate and creates nothing, while the same origin without the alias succeeds."""
    require_tools("aws")

    region = ctx.region
    marker = ctx.unique_name("sim2real-cfcert-")
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-cfcert-api-"))["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    apigw_domain = f"{api_id}.execute-api.{region}.amazonaws.com"
    domain_label = re.sub(r"[^a-z0-9-]", "-", marker.lower()).strip("-")
    # A unique name under a public TLD: CloudFront's CNAME syntax check refuses reserved names such as
    # example.com before it reaches the certificate requirement under test.
    custom_domain = f"{domain_label}.com"

    def _origin_config():
        return {
            "Quantity": 1,
            "Items": [
                {
                    "Id": "apigw-origin",
                    "DomainName": apigw_domain,
                    "CustomOriginConfig": {
                        "HTTPPort": 80,
                        "HTTPSPort": 443,
                        "OriginProtocolPolicy": "https-only",
                        "OriginSslProtocols": {"Quantity": 1, "Items": ["TLSv1.2"]},
                    },
                }
            ],
        }

    def _default_cache_behavior():
        return {
            "TargetOriginId": "apigw-origin",
            "ViewerProtocolPolicy": "allow-all",
            "AllowedMethods": {
                "Quantity": 2,
                "Items": ["GET", "HEAD"],
                "CachedMethods": {"Quantity": 2, "Items": ["GET", "HEAD"]},
            },
            "ForwardedValues": {"QueryString": True, "Cookies": {"Forward": "all"}},
            "MinTTL": 0,
            "DefaultTTL": 0,
            "MaxTTL": 0,
            "Compress": False,
        }

    # --- broken: alternate domain name with no ACM cert (default CloudFront cert only) ---
    bad_config = {
        "CallerReference": marker + "-bad",
        "Comment": marker + "-bad",
        "Enabled": True,
        "Aliases": {"Quantity": 1, "Items": [custom_domain]},
        "ViewerCertificate": {"CloudFrontDefaultCertificate": True},
        "Origins": _origin_config(),
        "DefaultCacheBehavior": _default_cache_behavior(),
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(bad_config, f)
        bad_path = f.name
    try:
        proc = _run_shell(
            ctx,
            [
                "aws",
                "--output",
                "json",
                "cloudfront",
                "create-distribution",
                "--distribution-config",
                f"file://{bad_path}",
            ],
            check=False,
        )
    finally:
        os.unlink(bad_path)

    assert proc.returncode != 0, (
        "CLI create-distribution with alias + default cert unexpectedly succeeded"
    )
    # CloudFront refuses an alias that no attached certificate covers before creating anything.
    error = _cli_error(proc.stderr)
    assert error == (
        "InvalidViewerCertificate",
        "To add an alternate domain name (CNAME) to a CloudFront distribution, you must attach a "
        "trusted certificate that validates your authorization to use the domain name. For more "
        "details, see: https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/"
        "CNAMEs.html#alternate-domain-names-requirements",
    ), f"unexpected rejection: {error!r} ({proc.stderr[-400:]!r})"

    # effect absent: no distribution anywhere carries the alias we tried to attach
    cf = ctx.client("cloudfront")
    paginator = cf.get_paginator("list_distributions")
    leaked = []
    for page in paginator.paginate():
        for dist in page.get("DistributionList", {}).get("Items", []):
            if custom_domain in (dist.get("Aliases", {}).get("Items") or []):
                leaked.append(dist["Id"])
    assert not leaked, f"a distribution was created for the rejected alias: {leaked}"

    # --- positive control: identical origin, no alias/cert involved -> succeeds ---
    good_config = {
        "CallerReference": marker + "-good",
        "Comment": marker + "-good",
        "Enabled": True,
        "Origins": _origin_config(),
        "DefaultCacheBehavior": _default_cache_behavior(),
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(good_config, f)
        good_path = f.name
    try:
        created = _run_aws(
            ctx,
            "cloudfront",
            "create-distribution",
            "--distribution-config",
            f"file://{good_path}",
        )
    finally:
        os.unlink(good_path)

    good_dist_id = created["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _cf_disable_and_delete(ctx, good_dist_id))
    assert created["Distribution"]["Status"] in ("InProgress", "Deployed"), (
        f"expected InProgress or Deployed right after create, got {created['Distribution']['Status']!r}"
    )

    # independent read, at the destination, through a different operation than the one that
    # mutated -- proves the distribution the CLI reported is the one CloudFront actually holds.
    fetched = cf.get_distribution(Id=good_dist_id)["Distribution"]
    assert fetched["Id"] == good_dist_id, (
        f"get_distribution returned {fetched['Id']!r}, expected {good_dist_id!r}"
    )
    assert fetched["DistributionConfig"]["Aliases"]["Quantity"] == 0, (
        f"expected 0 aliases on the alias-free distribution, got "
        f"{fetched['DistributionConfig']['Aliases']['Quantity']}"
    )
    assert custom_domain not in (
        fetched["DistributionConfig"]["Aliases"].get("Items") or []
    ), (
        f"the rejected alias {custom_domain!r} leaked onto the unrelated good distribution"
    )


def _run_shell(ctx, command, *, env_extra=None, timeout_s=60.0, check=True, cwd=None):
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    if env_extra:
        env.update(env_extra)
    result = subprocess.run(
        command,
        shell=isinstance(command, str),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout_s,
        cwd=cwd,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"Command failed (rc={result.returncode}):\n  cmd: {command}\n"
            f"  stderr: {result.stderr[-500:]}"
        )
    return result


def _run_aws(ctx, *args: str, timeout_s=30.0, check=True):
    proc = _run_shell(
        ctx, ["aws", "--output", "json", *args], timeout_s=timeout_s, check=check
    )
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


def _cli_error(stderr: str):
    """The (code, message) of an `aws` CLI failure of the form
    'An error occurred (SomeErrorCode) when calling the X operation: message'."""
    match = re.search(
        r"An error occurred \(([A-Za-z0-9]+)\) when calling the \w+ operation: (.*)", stderr
    )
    return (match.group(1), match.group(2).strip()) if match else (None, None)


def _cf_disable_and_delete(ctx, dist_id):
    cf = ctx.client("cloudfront")
    cfg_resp = cf.get_distribution_config(Id=dist_id)
    config = cfg_resp["DistributionConfig"]
    etag = cfg_resp["ETag"]
    if config.get("Enabled"):
        config["Enabled"] = False
        update_resp = cf.update_distribution(
            Id=dist_id, DistributionConfig=config, IfMatch=etag
        )
        etag = update_resp["ETag"]
    deadline = time.monotonic() + 1500.0
    while time.monotonic() < deadline:
        resp = cf.get_distribution(Id=dist_id)
        if resp["Distribution"]["Status"] == "Deployed":
            etag = cf.get_distribution_config(Id=dist_id)["ETag"]
            break
        time.sleep(15.0)
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
