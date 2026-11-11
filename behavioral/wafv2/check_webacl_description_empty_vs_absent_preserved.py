"""webacl-description-empty-vs-absent-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "webacl-description-empty-vs-absent-preserved"
GROUP = "representation"
SERVICES = ["wafv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetWebACL returns Description "" when CreateWebACL omits it, the value an UpdateWebACL sets, and ""
    again after an UpdateWebACL that omits it.
    """
    wafv2 = ctx.client("wafv2")
    scope = "REGIONAL"
    name = ctx.unique_name("sim2real-behav-webacl-desc-")

    created = wafv2.create_web_acl(
        Name=name,
        Scope=scope,
        DefaultAction={"Allow": {}},
        VisibilityConfig=_visibility_config("descaclmetric"),
    )
    web_acl_id = created["Summary"]["Id"]
    ctx.on_cleanup(lambda: wafv2.delete_web_acl(
        Name=name, Scope=scope, Id=web_acl_id,
        LockToken=wafv2.get_web_acl(Name=name, Scope=scope, Id=web_acl_id)["LockToken"],
    ))

    got = wafv2.get_web_acl(Name=name, Scope=scope, Id=web_acl_id)
    assert got["WebACL"].get("Description") == "", (
        f"expected Description normalized to empty string when omitted on create, got: {got['WebACL'].get('Description')!r}"
    )

    wafv2.update_web_acl(
        Name=name,
        Scope=scope,
        Id=web_acl_id,
        DefaultAction={"Allow": {}},
        Description="now-has-a-description",
        VisibilityConfig=_visibility_config("descaclmetric"),
        LockToken=got["LockToken"],
    )
    got2 = wafv2.get_web_acl(Name=name, Scope=scope, Id=web_acl_id)
    assert got2["WebACL"].get("Description") == "now-has-a-description", (
        f"expected Description set by update to round-trip, got: {got2['WebACL'].get('Description')!r}"
    )

    wafv2.update_web_acl(
        Name=name,
        Scope=scope,
        Id=web_acl_id,
        DefaultAction={"Allow": {}},
        VisibilityConfig=_visibility_config("descaclmetric"),
        LockToken=got2["LockToken"],
    )
    got3 = wafv2.get_web_acl(Name=name, Scope=scope, Id=web_acl_id)
    assert got3["WebACL"].get("Description") == "", (
        f"expected Description reset to empty string when omitted on update, got: {got3['WebACL'].get('Description')!r}"
    )


def _visibility_config(metric_name: str) -> dict:
    return {
        "SampledRequestsEnabled": True,
        "CloudWatchMetricsEnabled": True,
        "MetricName": metric_name,
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

