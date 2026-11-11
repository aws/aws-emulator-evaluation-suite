"""update-resolver-config-toggle-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "update-resolver-config-toggle-lifecycle"
GROUP = "state-machine"
SERVICES = ["route53resolver"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateResolverConfig toggling AutodefinedReverseFlag drives the VPC's
    AutodefinedReverse status to DISABLED then back to ENABLED, visible through both
    GetResolverConfig and ListResolverConfigs."""
    r53r = ctx.client("route53resolver")
    ec2 = ctx.client("ec2")

    vpc_name = ctx.unique_name("sim2real-r53r-vpc-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.92.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": vpc_name}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    r53r.update_resolver_config(ResourceId=vpc_id, AutodefinedReverseFlag="DISABLE")
    status = _poll_autodefined_reverse(r53r, vpc_id, {"DISABLED"}, timeout_s=240.0)
    assert status == "DISABLED", f"got={status} expected=DISABLED (timed out waiting)"

    listed = _find_in_list_resolver_configs(r53r, vpc_id)
    assert listed is not None, "resolver config for VPC missing from ListResolverConfigs"
    assert listed["AutodefinedReverse"] == "DISABLED", (
        f"got={listed['AutodefinedReverse']!r} expected='DISABLED' via ListResolverConfigs"
    )

    r53r.update_resolver_config(ResourceId=vpc_id, AutodefinedReverseFlag="ENABLE")
    status2 = _poll_autodefined_reverse(r53r, vpc_id, {"ENABLED"}, timeout_s=240.0)
    assert status2 == "ENABLED", f"got={status2} expected=ENABLED (timed out waiting)"

    listed2 = _find_in_list_resolver_configs(r53r, vpc_id)
    assert listed2 is not None, "resolver config for VPC missing from ListResolverConfigs after re-enable"
    assert listed2["AutodefinedReverse"] == "ENABLED", (
        f"got={listed2['AutodefinedReverse']!r} expected='ENABLED' via ListResolverConfigs"
    )


def _poll_autodefined_reverse(r53r, vpc_id: str, terminal_statuses, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = r53r.get_resolver_config(ResourceId=vpc_id)["ResolverConfig"]["AutodefinedReverse"]
        if status in terminal_statuses:
            return status
        time.sleep(interval_s)
    return status


def _find_in_list_resolver_configs(r53r, vpc_id: str):
    paginator_kwargs = {"MaxResults": 100}
    next_token = None
    while True:
        if next_token:
            paginator_kwargs["NextToken"] = next_token
        page = r53r.list_resolver_configs(**paginator_kwargs)
        for cfg in page.get("ResolverConfigs", []):
            if cfg.get("ResourceId") == vpc_id:
                return cfg
        next_token = page.get("NextToken")
        if not next_token:
            return None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
