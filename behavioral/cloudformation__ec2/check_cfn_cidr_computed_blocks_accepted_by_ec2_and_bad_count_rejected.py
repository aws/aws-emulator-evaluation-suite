"""cfn-cidr-computed-blocks-accepted-by-ec2-and-bad-count-rejected."""

from __future__ import annotations

import ipaddress
import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-cidr-computed-blocks-accepted-by-ec2-and-bad-count-rejected"

GROUP = "deploy_intrinsics"

SERVICES = ["cloudformation", "ec2"]

# Every expectation below is derived from these inputs with the stdlib `ipaddress` module, never
# written out by hand, so the check is an independent reference implementation of Fn::Cidr.
VPC_BLOCK = "10.44.0.0/16"
WIDE_COUNT, WIDE_HOST_BITS = 6, 8      # 6 x /24 out of the /16
NARROW_BLOCK = "10.44.0.0/24"
NARROW_COUNT, NARROW_HOST_BITS = 4, 4  # 4 x /28 out of that /24
PICK_K, PICK_LAST = 3, 5               # the k-th and the LAST index of the wide list
OVER_COUNT_BLOCK = "10.45.0.0/16"      # count above Fn::Cidr's documented 256 ceiling
TINY_BLOCK = "10.46.0.0/16"            # host bits that compute a /31 -- below EC2's /28 floor
_CIDR_COUNT_MESSAGE = (
    "Template error: Template error: invalid count (300) of subnets requested. "
    "Count must be 1 to 256"
)
# AWS reserves the first four addresses and the broadcast address in every subnet.
AWS_RESERVED_PER_SUBNET = 5


def _cidr(block: str, count: int, host_bits: int) -> list[str]:
    """What Fn::Cidr(block, count, host_bits) must return, per RFC arithmetic.

    `cidrBits` counts HOST bits (8 out of a /16 yields /24s), not the new prefix length.
    """
    net = ipaddress.ip_network(block)
    subs = net.subnets(prefixlen_diff=net.max_prefixlen - net.prefixlen - host_bits)
    return [str(next(subs)) for _ in range(count)]


def _main_template() -> str:
    """A VPC, two subnets whose CidrBlock is computed by Fn::Cidr, and an ENI inside one of them."""
    wide = {"Fn::Cidr": [{"Fn::GetAtt": ["Vpc", "CidrBlock"]}, WIDE_COUNT, WIDE_HOST_BITS]}
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {
                "CidrBlock": VPC_BLOCK,
                "Tags": [{"Key": "sim2real", "Value": CHECK}]}},
            "SubnetK": {"Type": "AWS::EC2::Subnet", "Properties": {
                "VpcId": {"Ref": "Vpc"},
                "AvailabilityZone": {"Fn::Select": ["0", {"Fn::GetAZs": ""}]},
                "CidrBlock": {"Fn::Select": [str(PICK_K), wide]},
                "Tags": [{"Key": "sim2real", "Value": CHECK}]}},
            "SubnetLast": {"Type": "AWS::EC2::Subnet", "Properties": {
                "VpcId": {"Ref": "Vpc"},
                "AvailabilityZone": {"Fn::Select": ["1", {"Fn::GetAZs": ""}]},
                "CidrBlock": {"Fn::Select": [str(PICK_LAST), wide]},
                "Tags": [{"Key": "sim2real", "Value": CHECK}]}},
            "Eni": {"Type": "AWS::EC2::NetworkInterface", "Properties": {
                "SubnetId": {"Ref": "SubnetK"},
                "Tags": [{"Key": "sim2real", "Value": CHECK}]}},
        },
        "Outputs": {
            "AllBlocks": {"Value": {"Fn::Join": [",", wide]}},
            "Narrow": {"Value": {"Fn::Join": [",", {
                "Fn::Cidr": [NARROW_BLOCK, NARROW_COUNT, NARROW_HOST_BITS]}]}},
            "EniIp": {"Value": {"Fn::GetAtt": ["Eni", "PrimaryPrivateIpAddress"]}},
            "VpcId": {"Value": {"Ref": "Vpc"}},
            "SubnetKId": {"Value": {"Ref": "SubnetK"}},
            "SubnetLastId": {"Value": {"Ref": "SubnetLast"}},
            "EniId": {"Value": {"Ref": "Eni"}},
        },
    })


def _one_subnet_template(vpc_block: str, count: int, host_bits: int, index: int) -> str:
    """A VPC plus a single subnet whose block comes out of one Fn::Cidr call."""
    return json.dumps({
        "Resources": {
            "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {
                "CidrBlock": vpc_block,
                "Tags": [{"Key": "sim2real", "Value": CHECK}]}},
            "Doomed": {"Type": "AWS::EC2::Subnet", "Properties": {
                "VpcId": {"Ref": "Vpc"},
                "CidrBlock": {"Fn::Select": [str(index), {
                    "Fn::Cidr": [{"Fn::GetAtt": ["Vpc", "CidrBlock"]}, count, host_bits]}]},
                "Tags": [{"Key": "sim2real", "Value": CHECK}]}},
        },
    })


def _error(fn) -> tuple[str, str]:
    """The (Error.Code, Error.Message) fn() raises; AssertionError if the call succeeds."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError("call unexpectedly succeeded; expected it to raise a ClientError")


def _stack_events(cfn, stack: str) -> list[dict[str, Any]]:
    """Every event for a stack, oldest first, paginated."""
    events: list[dict[str, Any]] = []
    token = None
    while True:
        kwargs: dict[str, Any] = {"StackName": stack}
        if token:
            kwargs["NextToken"] = token
        page = cfn.describe_stack_events(**kwargs)
        events.extend(page.get("StackEvents", []))
        token = page.get("NextToken")
        if not token:
            break
    return list(reversed(events))


def _poll_until(probe, predicate, what: str, timeout_s=1200.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{what} not observed within {timeout_s}s (last observation: {last!r})")


def _wait_stack_status(cfn, stack: str, targets: set[str], timeout_s=1200.0) -> dict[str, Any]:
    def probe():
        try:
            return cfn.describe_stacks(StackName=stack)["Stacks"][0]
        except ClientError:
            return None

    return _poll_until(
        probe,
        lambda s: s is not None and s.get("StackStatus") in targets,
        f"stack {stack!r} reaching one of {sorted(targets)}",
        timeout_s=timeout_s,
    )


@tags("axis:rejection", "cap:c3", "cap:c5", "concern:deploy", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Fn::Cidr blocks match stdlib-derived CIDR arithmetic and EC2 records them verbatim; a count
    above 256 is refused by the template interpreter, while a computed /31 is refused by EC2 itself.
    """
    cfn = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")

    wide_expected = _cidr(VPC_BLOCK, WIDE_COUNT, WIDE_HOST_BITS)
    narrow_expected = _cidr(NARROW_BLOCK, NARROW_COUNT, NARROW_HOST_BITS)

    name = ctx.unique_name("sim2real-behav-cfn-cidr-")
    stack_id = cfn.create_stack(
        StackName=name, TemplateBody=_main_template(),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=stack_id))

    stack = _wait_stack_status(
        cfn, stack_id,
        {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"},
    )
    assert stack["StackStatus"] == "CREATE_COMPLETE", (
        f"the Fn::Cidr stack ended {stack['StackStatus']!r}: {stack.get('StackStatusReason')!r}"
    )
    out = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}

    # 1. the whole computed list, in order, against the RFC-derived expectation
    assert out["AllBlocks"].split(",") == wide_expected, (
        f"Fn::Cidr({VPC_BLOCK!r}, {WIDE_COUNT}, {WIDE_HOST_BITS}) returned "
        f"{out['AllBlocks'].split(',')!r}, expected {wide_expected!r}"
    )
    # 2. a second, differently shaped computation, so one hard-coded case cannot satisfy both.
    #    cidrBits counts HOST bits: 4 out of a /24 is a /28, not a /4.
    assert out["Narrow"].split(",") == narrow_expected, (
        f"Fn::Cidr({NARROW_BLOCK!r}, {NARROW_COUNT}, {NARROW_HOST_BITS}) returned "
        f"{out['Narrow'].split(',')!r}, expected {narrow_expected!r} -- cidrBits is a count of "
        f"host bits, not a prefix length"
    )

    subnets = {s["SubnetId"]: s for s in ec2.describe_subnets(
        SubnetIds=[out["SubnetKId"], out["SubnetLastId"]])["Subnets"]}
    sub_k, sub_last = subnets[out["SubnetKId"]], subnets[out["SubnetLastId"]]

    # 3/4. EC2's OWN record of the blocks CloudFormation computed -- the k-th and the LAST index,
    #      so an off-by-one in the subdivision cannot hide behind a correct middle element.
    assert sub_k["CidrBlock"] == wide_expected[PICK_K], (
        f"EC2 recorded {sub_k['CidrBlock']!r} for the Fn::Select[{PICK_K}] subnet, expected "
        f"{wide_expected[PICK_K]!r}"
    )
    assert sub_last["CidrBlock"] == wide_expected[PICK_LAST], (
        f"EC2 recorded {sub_last['CidrBlock']!r} for the LAST computed block "
        f"(Fn::Select[{PICK_LAST}]), expected {wide_expected[PICK_LAST]!r}"
    )

    # 5. IPAM semantics, not string handling: AWS reserves five addresses per subnet, and the ENI
    #    in SubnetK consumes exactly one more.
    usable = ipaddress.ip_network(wide_expected[PICK_LAST]).num_addresses - AWS_RESERVED_PER_SUBNET
    assert sub_last["AvailableIpAddressCount"] == usable, (
        f"the ENI-free subnet {sub_last['CidrBlock']} reports "
        f"{sub_last['AvailableIpAddressCount']!r} available addresses, expected {usable} "
        f"({ipaddress.ip_network(wide_expected[PICK_LAST]).num_addresses} minus AWS's "
        f"{AWS_RESERVED_PER_SUBNET} reserved)"
    )
    assert sub_k["AvailableIpAddressCount"] == usable - 1, (
        f"the subnet holding one ENI reports {sub_k['AvailableIpAddressCount']!r} available "
        f"addresses, expected {usable - 1}: the ENI must debit exactly one address"
    )

    # 6/7. a real ENI got an address INSIDE the computed range, and not a reserved one
    computed_net = ipaddress.ip_network(wide_expected[PICK_K])
    eni_ip = ipaddress.ip_address(out["EniIp"])
    assert eni_ip in computed_net, (
        f"the ENI was given {out['EniIp']!r}, which is outside the computed block "
        f"{computed_net!s} it was created in"
    )
    # AWS reserves the network address, the next three, and the broadcast address.
    reserved = {computed_net.network_address + i for i in range(4)} | {
        computed_net.broadcast_address}
    assert eni_ip not in reserved, (
        f"the ENI was given {out['EniIp']!r}, one of the {len(reserved)} addresses AWS reserves "
        f"in {computed_net!s} ({sorted(str(a) for a in reserved)!r})"
    )

    # 8. control on the other computed intrinsic in the same template
    assert sub_k["AvailabilityZone"] != sub_last["AvailabilityZone"], (
        f"both subnets landed in {sub_k['AvailabilityZone']!r}; Fn::Select over Fn::GetAZs must "
        f"resolve indices 0 and 1 to different zones"
    )

    # 9. the computation really consumed the VPC's own attribute
    vpc_block = ec2.describe_vpcs(VpcIds=[out["VpcId"]])["Vpcs"][0]["CidrBlock"]
    assert vpc_block == VPC_BLOCK, f"EC2 recorded the VPC block as {vpc_block!r}"
    assert all(ipaddress.ip_network(b).subnet_of(ipaddress.ip_network(vpc_block))
               for b in wide_expected), (
        f"computed blocks {wide_expected!r} are not all inside the VPC block {vpc_block!r}"
    )

    # --- arm 1: a count above Fn::Cidr's ceiling is refused by the INTERPRETER ----------------
    over_name = ctx.unique_name("sim2real-behav-cfn-cidr-over-")
    code, message = _error(lambda: cfn.create_stack(
        StackName=over_name,
        TemplateBody=_one_subnet_template(OVER_COUNT_BLOCK, 300, WIDE_HOST_BITS, 299),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    ))
    # 10. exact code, and a message that names the count rather than a generic template error
    assert code == "ValidationError", (
        f"an Fn::Cidr count of 300 was answered with {code!r} ({message[:200]!r}), expected "
        f"'ValidationError'"
    )
    assert message == _CIDR_COUNT_MESSAGE, (
        f"the refusal message was {message!r}; it must name Fn::Cidr's count range"
    )
    # 11. effect-absent: the whole stack was refused, so nothing was created at all
    absent_code, absent_message = _error(lambda: cfn.describe_stacks(StackName=over_name))
    assert absent_code == "ValidationError", (
        f"describe_stacks on the refused stack {over_name!r} answered {absent_code!r}; the "
        f"synchronous refusal must have created no stack"
    )
    assert absent_message == f"Stack with id {over_name} does not exist", (
        f"describe_stacks on the refused stack {over_name!r}: unexpected message {absent_message!r}"
    )

    # --- arm 2: a computed block below EC2's /28 floor is refused by EC2 ----------------------
    tiny_expected = _cidr(TINY_BLOCK, 2, 1)
    tiny_name = ctx.unique_name("sim2real-behav-cfn-cidr-tiny-")
    tiny_id = cfn.create_stack(
        StackName=tiny_name,
        TemplateBody=_one_subnet_template(TINY_BLOCK, 2, 1, 0),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=tiny_id))
    tiny = _wait_stack_status(
        cfn, tiny_id, {"CREATE_COMPLETE", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "CREATE_FAILED"})
    assert tiny["StackStatus"] == "ROLLBACK_COMPLETE", (
        f"a subnet computed as {tiny_expected[0]!r} left the stack {tiny['StackStatus']!r}; EC2's "
        f"minimum subnet size is /28, so the create must fail and roll back"
    )
    tiny_events = _stack_events(cfn, tiny_id)
    failures = [e for e in tiny_events
                if e.get("LogicalResourceId") == "Doomed"
                and e.get("ResourceStatus") == "CREATE_FAILED"]
    assert failures, (
        f"no CREATE_FAILED event for the doomed subnet; events were "
        f"{[(e.get('LogicalResourceId'), e.get('ResourceStatus')) for e in tiny_events]!r}"
    )
    reason = failures[0].get("ResourceStatusReason") or ""
    # message varies: the handler reason embeds a per-call Request ID and RequestToken.
    # 12. the refusal names the block Fn::Cidr computed, i.e. the computed string reached EC2's
    #     validator unmodified and was rejected THERE, not by the template interpreter.
    assert f"The CIDR '{tiny_expected[0]}' is invalid" in reason, (
        f"the failure reason was {reason!r}; it must name the computed block "
        f"{tiny_expected[0]!r} rejected by EC2"
    )
    assert not [e for e in tiny_events
                if e.get("LogicalResourceId") == "Doomed"
                and e.get("ResourceStatus") == "CREATE_COMPLETE"], (
        "the doomed subnet reported CREATE_COMPLETE as well as CREATE_FAILED"
    )
    # 13. effect-absent: the rolled-back VPC is really gone, by physical id
    doomed_vpc = [e.get("PhysicalResourceId") for e in tiny_events
                  if e.get("LogicalResourceId") == "Vpc" and e.get("PhysicalResourceId")]
    assert doomed_vpc, "no PhysicalResourceId was ever recorded for the rolled-back VPC"
    vpc_code, vpc_message = _error(lambda: ec2.describe_vpcs(VpcIds=[doomed_vpc[-1]]))
    assert vpc_code == "InvalidVpcID.NotFound", (
        f"the rolled-back VPC {doomed_vpc[-1]!r} answers describe_vpcs with {vpc_code!r}"
    )
    assert vpc_message == f"The vpc ID '{doomed_vpc[-1]}' does not exist", (
        f"describe_vpcs on the rolled-back VPC: unexpected message {vpc_message!r}"
    )

    # --- teardown with verification -----------------------------------------------------------
    cfn.delete_stack(StackName=stack_id)
    deleted = _wait_stack_status(cfn, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"})
    assert deleted["StackStatus"] == "DELETE_COMPLETE", (
        f"delete ended {deleted['StackStatus']!r}: {deleted.get('StackStatusReason')!r}"
    )
    # 14. post-delete effect-absent on both the VPC and the ENI inside the computed subnet
    gone_vpc, gone_vpc_message = _error(lambda: ec2.describe_vpcs(VpcIds=[out["VpcId"]]))
    assert gone_vpc == "InvalidVpcID.NotFound", (
        f"the VPC {out['VpcId']!r} still exists after DELETE_COMPLETE (code {gone_vpc!r})"
    )
    assert gone_vpc_message == f"The vpc ID '{out['VpcId']}' does not exist", (
        f"describe_vpcs on the deleted VPC: unexpected message {gone_vpc_message!r}"
    )
    gone_eni, gone_eni_message = _error(lambda: ec2.describe_network_interfaces(
        NetworkInterfaceIds=[out["EniId"]]))
    assert gone_eni == "InvalidNetworkInterfaceID.NotFound", (
        f"the ENI {out['EniId']!r} still exists after DELETE_COMPLETE (code {gone_eni!r})"
    )
    assert gone_eni_message == f"The networkInterface ID '{out['EniId']}' does not exist", (
        f"describe_network_interfaces on the deleted ENI: unexpected message {gone_eni_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
