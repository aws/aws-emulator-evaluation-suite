"""traffic-mirror-filter-rule-target-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _probe_errors(client, probes):
    """Assert a batch of operations all fail with an expected AWS-side error code.

    *probes* is a list of ``(client_method, kwargs, acceptable_codes)``. Every
    mismatch is collected rather than raising on the first, and operations the
    installed botocore does not know about are reported as skipped. A
    ``ParamValidationError`` (the request never left the SDK) is deliberately left
    uncaught: it must not be conflated with an AWS-side semantic rejection, and
    letting it propagate still fails the check. Returns ``(problems, skipped)``.
    """
    problems = []
    skipped = []
    for method, kwargs, expected in probes:
        fn = getattr(client, method, None)
        if fn is None:
            skipped.append(method)
            continue
        try:
            fn(**kwargs)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in expected:
                problems.append(f"{method}: expected {sorted(expected)}, got {code}")
        else:
            problems.append(f"{method}: expected {sorted(expected)} but the call SUCCEEDED")
    return problems, skipped

CHECK = "traffic-mirror-filter-rule-target-lifecycle"
GROUP = 'vpc-networking'
SERVICES = ['ec2']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Traffic mirror filter/rule/target creation and rule-number conflict semantics."""
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(CidrBlock="10.104.0.0/16", TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "sim2real", "Value": "1"}]}])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["State"] == "available":
            break
        time.sleep(2)

    subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.104.1.0/24", TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "sim2real", "Value": "1"}]}])["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))

    filt = ec2.create_traffic_mirror_filter(Description="behavioral check", TagSpecifications=[{"ResourceType": "traffic-mirror-filter", "Tags": [{"Key": "sim2real", "Value": "1"}]}])
    filter_id = filt["TrafficMirrorFilter"]["TrafficMirrorFilterId"]
    ctx.on_cleanup(lambda: ec2.delete_traffic_mirror_filter(TrafficMirrorFilterId=filter_id))

    rule_args = dict(
        TrafficMirrorFilterId=filter_id,
        TrafficDirection="ingress",
        RuleNumber=100,
        RuleAction="accept",
        DestinationCidrBlock="10.104.0.0/16",
        SourceCidrBlock="0.0.0.0/0",
    )
    rule = ec2.create_traffic_mirror_filter_rule(**rule_args)
    got_number = rule["TrafficMirrorFilterRule"]["RuleNumber"]
    assert got_number == 100, f"expected RuleNumber 100, got {got_number}"

    problems, _ = _probe_errors(ec2, [
        ("create_traffic_mirror_filter_rule", rule_args,
         ("TrafficMirrorFilterRuleAlreadyExists",)),
    ])

    # Independent read at the destination: the conflicting create must not have produced a
    # second rule numbered 100 on the filter.
    ingress_100 = [
        r for r in ec2.describe_traffic_mirror_filters(TrafficMirrorFilterIds=[filter_id])
        ["TrafficMirrorFilters"][0]["IngressFilterRules"]
        if r["RuleNumber"] == 100
    ]
    assert len(ingress_100) == 1, (
        f"expected exactly 1 rule numbered 100 on {filter_id} after the rejected duplicate "
        f"create, found {len(ingress_100)}"
    )

    eni = ec2.create_network_interface(SubnetId=subnet_id, Description="mirror target", TagSpecifications=[{"ResourceType": "network-interface", "Tags": [{"Key": "sim2real", "Value": "1"}]}])
    eni_id = eni["NetworkInterface"]["NetworkInterfaceId"]
    ctx.on_cleanup(lambda: ec2.delete_network_interface(NetworkInterfaceId=eni_id))

    # A free-standing (unattached) ENI is NOT a valid traffic mirror target: real AWS requires
    # the target network interface be attached to a supported (Nitro) instance, rejecting a bare
    # ENI with NetworkInterfaceNotSupported. (An emulator that accepts a free-standing ENI as a
    # mirror target would be over-permissive.)
    tgt_problems, _ = _probe_errors(ec2, [
        (
            "create_traffic_mirror_target",
            {
                "NetworkInterfaceId": eni_id,
                "Description": "behavioral target",
                "TagSpecifications": [{"ResourceType": "traffic-mirror-target", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
            },
            ("NetworkInterfaceNotSupported",),
        ),
    ])
    problems += tgt_problems

    more, _ = _probe_errors(ec2, [
        # Specifying two target types at once must be refused.
        (
            "create_traffic_mirror_target",
            {
                "NetworkInterfaceId": eni_id,
                "NetworkLoadBalancerArn": (
                    f"arn:aws:elasticloadbalancing:{ctx.region}:111122223333:"
                    "loadbalancer/net/nope/0123456789abcdef"
                ),
            },
            ("InvalidParameterCombination", "InvalidParameterValue",
             "NetworkInterfaceNotSupported", "InvalidNetworkLoadBalancerArn.NotFound"),
        ),
        # And a session referencing unknown target/filter ids must be refused.
        (
            "create_traffic_mirror_session",
            {
                "NetworkInterfaceId": eni_id,
                "TrafficMirrorTargetId": "tmt-0123456789abcdef0",
                "TrafficMirrorFilterId": filter_id,
                "SessionNumber": 1,
            },
            (
                "InvalidTrafficMirrorTargetId.NotFound",
                "InvalidTrafficMirrorTargetID.NotFound",
                "NetworkInterfaceNotSupported",
                "InvalidParameterValue",
            ),
        ),
    ])
    problems += more
    assert not problems, "unexpected traffic-mirror semantics:\n" + "\n".join(problems)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
