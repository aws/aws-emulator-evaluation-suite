"""distribution-origin-custom-header-update-round-trip."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "distribution-origin-custom-header-update-round-trip"
GROUP = "origin-config"
SERVICES = ["cloudfront"]

MANAGED_CACHING_DISABLED = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"


def _custom_origin(origin_id: str, domain: str, headers: list[dict] | None = None) -> dict:
    origin: dict = {
        "Id": origin_id,
        "DomainName": domain,
        "CustomOriginConfig": {
            "HTTPPort": 80,
            "HTTPSPort": 443,
            "OriginProtocolPolicy": "match-viewer",
        },
    }
    if headers is not None:
        origin["CustomHeaders"] = {"Quantity": len(headers), "Items": headers}
    return origin


def _origin_by_id(origins: dict, origin_id: str) -> dict:
    for item in origins["Items"]:
        if item["Id"] == origin_id:
            return item
    raise AssertionError(f"origin {origin_id!r} missing from {origins!r}")


def _distribution_summary(cf, dist_id: str) -> dict:
    paginator = cf.get_paginator("list_distributions")
    for page in paginator.paginate():
        for summary in page["DistributionList"].get("Items", []):
            if summary["Id"] == dist_id:
                return summary
    raise AssertionError(f"distribution {dist_id!r} not found in ListDistributions")


def _await_deployed(cf, dist_id: str, *, timeout_s: float = 1200.0, interval_s: float = 15.0) -> str:
    """Poll GetDistribution to the terminal 'Deployed' status; return the latest ETag."""
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        resp = cf.get_distribution(Id=dist_id)
        status = resp["Distribution"]["Status"]
        if status == "Deployed":
            return resp["ETag"]
        time.sleep(interval_s)
    raise AssertionError(f"distribution {dist_id!r} still {status!r} after {timeout_s}s")


def _retire_distribution(cf, dist_id: str) -> None:
    cfg_resp = cf.get_distribution_config(Id=dist_id)
    cfg = cfg_resp["DistributionConfig"]
    etag = cfg_resp["ETag"]
    if cfg["Enabled"]:
        cfg["Enabled"] = False
        cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=cfg)
    etag = _await_deployed(cf, dist_id)
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A distribution's per-origin CustomHeaders round-trip through CreateDistribution,
    GetDistributionConfig and ListDistributions; UpdateDistribution's replaced header
    value plus an added header read back exactly, and the header-less origin stays at 0.
    """
    cf = ctx.client("cloudfront")

    header_name = "X-Sim-Replay-Token"
    initial_value = f"{ctx.unique_name('sim2real-behav-cfhdr-val-')}-v1"
    domain_a = f"{ctx.unique_name('sim2real-behav-cfhdr-a-')}.example.com"
    domain_b = f"{ctx.unique_name('sim2real-behav-cfhdr-b-')}.example.com"

    origin_with_header = _custom_origin(
        "origin-with-header", domain_a, [{"HeaderName": header_name, "HeaderValue": initial_value}]
    )
    origin_without_header = _custom_origin("origin-without-header", domain_b)

    config = {
        "CallerReference": ctx.unique_name("sim2real-behav-cfhdr-ref-"),
        "Comment": "",
        "Enabled": True,
        "Origins": {"Quantity": 2, "Items": [origin_with_header, origin_without_header]},
        "DefaultCacheBehavior": {
            "TargetOriginId": "origin-with-header",
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": MANAGED_CACHING_DISABLED,
        },
    }
    created = cf.create_distribution(DistributionConfig=config)
    dist_id = created["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _retire_distribution(cf, dist_id))

    created_origins = created["Distribution"]["DistributionConfig"]["Origins"]
    with_header = _origin_by_id(created_origins, "origin-with-header")
    assert with_header["CustomHeaders"]["Quantity"] == 1, (
        f"CreateDistribution echoed CustomHeaders.Quantity={with_header['CustomHeaders']['Quantity']!r}"
        " for the configured origin, expected 1"
    )
    assert with_header["CustomHeaders"]["Items"] == [
        {"HeaderName": header_name, "HeaderValue": initial_value}
    ], f"CreateDistribution echoed headers {with_header['CustomHeaders']['Items']!r}"
    without_header = _origin_by_id(created_origins, "origin-without-header")
    assert without_header["CustomHeaders"]["Quantity"] == 0, (
        f"CreateDistribution gave CustomHeaders.Quantity="
        f"{without_header['CustomHeaders']['Quantity']!r} for the header-less origin, expected 0"
    )

    got_cfg = cf.get_distribution_config(Id=dist_id)["DistributionConfig"]
    got_with_header = _origin_by_id(got_cfg["Origins"], "origin-with-header")
    assert got_with_header["CustomHeaders"]["Items"] == [
        {"HeaderName": header_name, "HeaderValue": initial_value}
    ], f"GetDistributionConfig returned headers {got_with_header['CustomHeaders']['Items']!r}"
    got_without_header = _origin_by_id(got_cfg["Origins"], "origin-without-header")
    assert got_without_header["CustomHeaders"]["Quantity"] == 0, (
        f"GetDistributionConfig gave CustomHeaders.Quantity="
        f"{got_without_header['CustomHeaders']['Quantity']!r}, expected 0"
    )

    summary = _distribution_summary(cf, dist_id)
    summary_with_header = _origin_by_id(summary["Origins"], "origin-with-header")
    assert summary_with_header["CustomHeaders"]["Items"] == [
        {"HeaderName": header_name, "HeaderValue": initial_value}
    ], f"ListDistributions returned headers {summary_with_header['CustomHeaders']['Items']!r}"
    summary_without_header = _origin_by_id(summary["Origins"], "origin-without-header")
    assert summary_without_header["CustomHeaders"]["Quantity"] == 0, (
        f"ListDistributions gave CustomHeaders.Quantity="
        f"{summary_without_header['CustomHeaders']['Quantity']!r}, expected 0"
    )

    replaced_value = f"{ctx.unique_name('sim2real-behav-cfhdr-val-')}-v2"
    added_name = "X-Sim-Replay-Token-2"
    added_value = f"{ctx.unique_name('sim2real-behav-cfhdr-val-')}-added"

    pre_update = cf.get_distribution_config(Id=dist_id)
    etag = pre_update["ETag"]
    updated_cfg = pre_update["DistributionConfig"]
    updated_origin = _origin_by_id(updated_cfg["Origins"], "origin-with-header")
    updated_origin["CustomHeaders"] = {
        "Quantity": 2,
        "Items": [
            {"HeaderName": header_name, "HeaderValue": replaced_value},
            {"HeaderName": added_name, "HeaderValue": added_value},
        ],
    }
    updated = cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=updated_cfg)

    updated_headers = _origin_by_id(
        updated["Distribution"]["DistributionConfig"]["Origins"], "origin-with-header"
    )["CustomHeaders"]
    expected_headers = sorted(
        [
            {"HeaderName": header_name, "HeaderValue": replaced_value},
            {"HeaderName": added_name, "HeaderValue": added_value},
        ],
        key=lambda h: h["HeaderName"],
    )
    assert updated_headers["Quantity"] == 2, (
        f"UpdateDistribution echoed CustomHeaders.Quantity={updated_headers['Quantity']!r}, expected 2"
    )
    assert sorted(updated_headers["Items"], key=lambda h: h["HeaderName"]) == expected_headers, (
        f"UpdateDistribution echoed headers {updated_headers['Items']!r}"
    )

    reread_cfg = cf.get_distribution_config(Id=dist_id)["DistributionConfig"]
    reread_with_header = _origin_by_id(reread_cfg["Origins"], "origin-with-header")
    assert sorted(reread_with_header["CustomHeaders"]["Items"], key=lambda h: h["HeaderName"]) == (
        expected_headers
    ), f"a later GetDistributionConfig returned headers {reread_with_header['CustomHeaders']['Items']!r}"
    reread_without_header = _origin_by_id(reread_cfg["Origins"], "origin-without-header")
    assert reread_without_header["CustomHeaders"]["Quantity"] == 0, (
        "the header-less origin gained headers after an unrelated update: "
        f"CustomHeaders.Quantity={reread_without_header['CustomHeaders']['Quantity']!r}"
    )

    reread_summary = _distribution_summary(cf, dist_id)
    reread_summary_with_header = _origin_by_id(reread_summary["Origins"], "origin-with-header")
    assert sorted(
        reread_summary_with_header["CustomHeaders"]["Items"], key=lambda h: h["HeaderName"]
    ) == expected_headers, (
        f"ListDistributions returned headers {reread_summary_with_header['CustomHeaders']['Items']!r}"
        " after the update"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
