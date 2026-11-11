"""browser-vpc-network-mode-requires-real-vpc-config."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "browser-vpc-network-mode-requires-real-vpc-config"
GROUP = "error-semantics"
SERVICES = ["bedrock-agentcore-control"]


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """A VPC-mode browser is refused without a vpcConfig and refused (or left unusable) when its
    vpcConfig names a well-formed subnet that does not exist, while the same call with the real
    VPC this check created converges to READY and echoes those exact ids back."""
    bac = ctx.client("bedrock-agentcore-control")
    net = _create_vpc(ctx)

    # Negative 1 — VPC mode with the vpcConfig omitted entirely.
    missing_cfg_name = _sandbox_name(ctx, "sim2realvpcnocfg")
    code = _error_code_or_raise(
        lambda: bac.create_browser(
            name=missing_cfg_name,
            networkConfiguration={"networkMode": "VPC"},
            tags={"sim2real": CHECK},
        ),
        subject=f"CreateBrowser({missing_cfg_name}) with networkMode=VPC and no vpcConfig",
    )
    assert code == "ValidationException", (
        f"expected ValidationException for networkMode=VPC with no vpcConfig, got {code!r}"
    )
    assert not _browser_named(bac, missing_cfg_name), (
        f"browser {missing_cfg_name!r} is listed despite CreateBrowser failing with {code!r}"
    )

    # Negative 2 — a vpcConfig whose subnet is well-formed but does not exist. Derived from a real
    # subnet id by rotating characters, so it satisfies ^subnet-[0-9a-zA-Z]{8,17}$ without being
    # fabricated from a guessed format.
    real_subnets = net["subnets"]
    absent_subnet = _rotate_id(real_subnets[0])
    assert absent_subnet not in real_subnets, (
        f"failed to derive an absent subnet id: {absent_subnet!r} collides with "
        f"{real_subnets!r}"
    )
    assert not _subnet_exists(ctx, absent_subnet), (
        f"premise broken: {absent_subnet!r} actually exists in this account, so the negative "
        f"would assert nothing"
    )
    absent_name = _sandbox_name(ctx, "sim2realvpcbadsub")
    absent_kwargs = {
        "name": absent_name,
        "networkConfiguration": {
            "networkMode": "VPC",
            "vpcConfig": {
                "subnets": [absent_subnet],
                "securityGroups": [net["security_group"]],
            },
        },
        "tags": {"sim2real": CHECK},
    }
    raised = None
    accepted = None
    try:
        accepted = bac.create_browser(**absent_kwargs)
    except ClientError as err:
        raised = err.response["Error"]["Code"]

    if raised is not None:
        assert raised == "ValidationException", (
            f"expected ValidationException for a vpcConfig naming the nonexistent subnet "
            f"{absent_subnet!r}, got {raised!r}"
        )
        assert not _browser_named(bac, absent_name), (
            f"browser {absent_name!r} is listed despite CreateBrowser failing with {raised!r}"
        )
    else:
        bad_id = accepted["browserId"]
        ctx.on_cleanup(lambda: _delete_browser(bac, bad_id))
        settled = _poll_until(
            lambda: bac.get_browser(browserId=bad_id),
            lambda b: b["status"] != "CREATING",
            "a VPC-mode browser bound to a nonexistent subnet to reach a terminal status",
            timeout_s=300.0,
        )
        assert settled["status"] != "READY", (
            f"a browser bound to the nonexistent subnet {absent_subnet!r} reached READY: "
            f"failureReason={settled.get('failureReason')!r}"
        )

    # Positive control: the same shape of call, with the real VPC this check created.
    good_name = _sandbox_name(ctx, "sim2realvpcgood")
    created = bac.create_browser(
        name=good_name,
        networkConfiguration={
            "networkMode": "VPC",
            "vpcConfig": {
                "subnets": real_subnets,
                "securityGroups": [net["security_group"]],
            },
        },
        tags={"sim2real": CHECK},
    )
    good_id = created["browserId"]
    ctx.on_cleanup(lambda: _delete_browser_and_wait_for_enis(ctx, bac, good_id, net["vpc"]))
    final = _poll_until(
        lambda: bac.get_browser(browserId=good_id),
        lambda b: b["status"] != "CREATING",
        "the VPC-mode browser with a real vpcConfig to leave CREATING",
        timeout_s=300.0,
    )
    assert final["status"] == "READY", (
        f"the positive control did not converge: status={final['status']!r} "
        f"failureReason={final.get('failureReason')!r} subnets={real_subnets!r}"
    )

    # Independent read at the resource: the declared binding must be reported back exactly.
    reported = final["networkConfiguration"]
    assert reported["networkMode"] == "VPC", (
        f"expected GetBrowser to report networkMode VPC, got {reported['networkMode']!r}"
    )
    reported_vpc = reported["vpcConfig"]
    assert set(reported_vpc["subnets"]) == set(real_subnets), (
        f"expected GetBrowser to report subnets {sorted(real_subnets)}, got "
        f"{sorted(reported_vpc['subnets'])}"
    )
    assert set(reported_vpc["securityGroups"]) == {net["security_group"]}, (
        f"expected GetBrowser to report security group {net['security_group']!r}, got "
        f"{sorted(reported_vpc['securityGroups'])}"
    )

    # Terminal read through a different operation than the mutation: only the accepted browser
    # is listed, and the two refused names are not.
    assert _browser_named(bac, good_name), (
        f"browser {good_name!r} reached READY but is not listed by ListBrowsers"
    )
    assert not _browser_named(bac, missing_cfg_name), (
        f"the browser refused for a missing vpcConfig ({missing_cfg_name!r}) appeared in "
        f"ListBrowsers after the positive control ran"
    )


# ===== helpers =====


def _poll_until(probe, predicate, reason, timeout_s=300.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {reason}; last value={last!r}")


def _error_code_or_raise(fn, subject):
    """RAISES on unexpected success rather than returning a falsy sentinel."""
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"]
    raise AssertionError(f"{subject} unexpectedly SUCCEEDED; expected it to be refused")


def _rotate_id(resource_id):
    """A well-formed-but-absent id, derived from a real one rather than invented."""
    last = resource_id[-1]
    return resource_id[:-1] + ("0" if last != "0" else "1")


def _subnet_exists(ctx, subnet_id):
    ec2 = ctx.client("ec2")
    try:
        resp = ec2.describe_subnets(SubnetIds=[subnet_id])
    except ClientError as err:
        if err.response["Error"]["Code"] in (
            "InvalidSubnetID.NotFound",
            "InvalidSubnetId.NotFound",
            "InvalidParameterValue",
        ):
            return False
        raise
    return len(resp["Subnets"]) > 0


def _sandbox_name(ctx, prefix):
    """SandboxName is ^[a-zA-Z][a-zA-Z0-9_]{0,47}$ — no hyphens."""
    raw = ctx.unique_name(f"{prefix}-")
    safe = "".join(c for c in raw if c.isalnum() or c == "_")
    if not safe[:1].isalpha():
        safe = "b" + safe
    return safe[:48]


def _browser_named(bac, name):
    next_token = None
    while True:
        kwargs = {"nextToken": next_token} if next_token else {}
        page = bac.list_browsers(**kwargs)
        for item in page["browserSummaries"]:
            if item.get("name") == name:
                return True
        next_token = page.get("nextToken")
        if not next_token:
            return False


def _delete_browser(bac, browser_id, timeout_s=180.0):
    try:
        bac.delete_browser(browserId=browser_id)
    except ClientError as err:
        if err.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    # Wait for the ENI to be released so the subnet delete that follows can succeed.
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            state = bac.get_browser(browserId=browser_id)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if state["status"] in ("DELETED", "DELETE_FAILED"):
            return
        time.sleep(4.0)
    raise AssertionError(
        f"browser {browser_id} did not finish deleting within {timeout_s}s; its ENI may still "
        f"hold the subnet this check created"
    )


def _delete_browser_and_wait_for_enis(ctx, bac, browser_id, vpc_id, timeout_s=420.0):
    """Teardown: delete the browser, then poll every 2 s until its ENIs leave the VPC.

    One 420 s deadline covers both steps; with the other browser (180 s) and the 3 x 80 s network
    deletes the waits add up to 840 s of the suite's 900 s cleanup budget.
    """
    deadline = time.monotonic() + timeout_s
    _delete_browser(bac, browser_id, timeout_s=180.0)
    ec2 = ctx.client("ec2")
    vpc_filter = [{"Name": "vpc-id", "Values": [vpc_id]}]
    while time.monotonic() < deadline:
        if not ec2.describe_network_interfaces(Filters=vpc_filter)["NetworkInterfaces"]:
            return
        time.sleep(2)


def _create_vpc(ctx):
    """No ambient default VPC: the check creates its own /16 with one subnet
    per available AZ (capped at two) and the VPC's default security group."""
    ec2 = ctx.client("ec2")
    tag_spec = [{"Key": "sim2real", "Value": CHECK}]

    vpc = ec2.create_vpc(
        CidrBlock="10.181.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": tag_spec}],
    )["Vpc"]
    vpc_id = vpc["VpcId"]
    ctx.on_cleanup(lambda: _retry_dependency(lambda: ec2.delete_vpc(VpcId=vpc_id), "delete_vpc"))
    ec2.get_waiter("vpc_available").wait(
        VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 30}
    )

    zones = [
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
    ]
    assert zones, (
        f"expected at least one available availability zone in {ctx.region}, got none"
    )
    subnets = []
    for index, zone in enumerate(zones[:2]):
        subnet = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.181.{index}.0/24",
            AvailabilityZone=zone,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": tag_spec}],
        )["Subnet"]
        subnet_id = subnet["SubnetId"]
        subnets.append(subnet_id)
        ctx.on_cleanup(
            lambda sid=subnet_id: _retry_dependency(
                lambda: ec2.delete_subnet(SubnetId=sid), f"delete_subnet({sid})"
            )
        )
    ec2.get_waiter("subnet_available").wait(
        SubnetIds=subnets, WaiterConfig={"Delay": 2, "MaxAttempts": 30}
    )

    groups = ec2.describe_security_groups(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "group-name", "Values": ["default"]},
        ]
    )["SecurityGroups"]
    assert len(groups) == 1, (
        f"expected exactly one default security group in the VPC this check created, got "
        f"{[g['GroupId'] for g in groups]!r}"
    )
    return {"vpc": vpc_id, "subnets": subnets, "security_group": groups[0]["GroupId"]}


def _retry_dependency(fn, label, timeout_s=80.0, interval_s=2.0):
    """A browser's ENI can outlive the DeleteBrowser call; retry only DependencyViolation."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            fn()
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code.endswith("NotFound") or code.endswith("NotFound.NotFound"):
                return
            if code != "DependencyViolation":
                raise
            time.sleep(interval_s)
    raise AssertionError(f"{label} still blocked by DependencyViolation after {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
