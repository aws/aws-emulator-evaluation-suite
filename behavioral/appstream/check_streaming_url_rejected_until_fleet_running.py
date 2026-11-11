"""streaming-url-rejected-until-fleet-running."""
from __future__ import annotations

import time
from datetime import datetime, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "streaming-url-rejected-until-fleet-running"
GROUP = "state"
SERVICES = ["appstream"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "dp:endpoint", "plane:control", "plane:data", "requires:appstream-service-access")
def run(ctx) -> None:
    """CreateStreamingURL is rejected with OperationNotPermittedException while the fleet is
    STOPPED; no URL is issued, and the same call after StartFleet reaches RUNNING (the
    positive control) returns a real, not-yet-expired StreamingURL."""
    appstream = ctx.client("appstream")
    vpc = _create_vpc(ctx)
    role_arn = _ensure_fleet_role(ctx)

    stack_name = ctx.unique_name("sim2real-appstream-stack-")
    appstream.create_stack(Name=stack_name)
    ctx.on_cleanup(lambda: appstream.delete_stack(Name=stack_name))

    fleet_name = ctx.unique_name("sim2real-appstream-fleet-")
    _retry_role_propagation(
        lambda: appstream.create_fleet(
            Name=fleet_name,
            InstanceType="stream.standard.small",
            FleetType="ELASTIC",
            Platform="WINDOWS_SERVER_2019",
            MaxConcurrentSessions=5,
            VpcConfig={"SubnetIds": vpc["subnet_ids"]},
            IamRoleArn=role_arn,
        )
    )
    ctx.on_cleanup(lambda: _delete_fleet_when_stopped(appstream, fleet_name))

    appstream.associate_fleet(FleetName=fleet_name, StackName=stack_name)
    ctx.on_cleanup(lambda: appstream.disassociate_fleet(FleetName=fleet_name, StackName=stack_name))

    user_id = "sim2real-streamuser1"

    code, message = _error(
        lambda: appstream.create_streaming_url(StackName=stack_name, FleetName=fleet_name, UserId=user_id)
    )
    assert code == "OperationNotPermittedException", (
        f"CreateStreamingURL against a STOPPED fleet must be rejected with OperationNotPermittedException; "
        f"got {code!r}"
    )
    expected_message = (
        f"The fleet {fleet_name} is not running. The stack must have a running fleet to get a streaming URL"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    stopped_sessions = appstream.describe_sessions(
        StackName=stack_name, FleetName=fleet_name, UserId=user_id, AuthenticationType="API"
    )["Sessions"]
    assert stopped_sessions == [], (
        f"a rejected CreateStreamingURL must not leave a streaming session for {user_id!r} visible "
        f"at DescribeSessions -- an independent read at the destination; got {stopped_sessions!r}"
    )

    appstream.start_fleet(Name=fleet_name)
    ctx.on_cleanup(lambda: appstream.stop_fleet(Name=fleet_name))
    _wait_for_fleet_state(ctx, fleet_name, "RUNNING", timeout_s=1200)

    result = appstream.create_streaming_url(StackName=stack_name, FleetName=fleet_name, UserId=user_id)
    assert result["StreamingURL"], "a RUNNING fleet must issue a non-empty StreamingURL"
    assert result["Expires"] > datetime.now(timezone.utc), (
        f"the issued StreamingURL must not already be expired; Expires={result['Expires']!r}"
    )

    # Independent read at the destination: CreateStreamingURL's own response is not enough to
    # tell a real reservation from a fabricated URL string. Visiting the URL (as a browser would)
    # makes AppStream's real backend authenticate the signature and redirect to a session-specific
    # `<hash>.appstream2.<region>.aws.amazon.com` host that echoes the exact fleet the session was
    # allocated against -- a redirect target no stub could produce without a real signed URL. (The
    # final 404 on that host's `/` is expected: it is a single-page app whose `#/...` route is
    # resolved client-side by JS a plain GET never runs, not a server error.)
    final_url = _visit_streaming_url(ctx, result["StreamingURL"])
    expected_reference = f"fleet%2F{fleet_name}"
    assert expected_reference in final_url, (
        f"visiting the StreamingURL must redirect to a session endpoint that references the real "
        f"fleet {fleet_name!r} it was issued for; got final URL {final_url!r}"
    )


# ===== helpers =====
def _ensure_fleet_role(ctx) -> str:
    """The IamRoleArn passed to CreateFleet is the 'machine role' assumed by streaming
    instances -- a distinct role from the account-level AppStream service-onboarding role.
    AppStream rejects reusing its own service-role as a fleet machine role, so this is a
    separate, shared (account-level) role."""
    import json

    iam = ctx.client("iam")
    role_name = "sim2real-appstream-fleet-machine-role"
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "appstream.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    try:
        role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy)["Role"]
    except iam.exceptions.EntityAlreadyExistsException:
        role = iam.get_role(RoleName=role_name)["Role"]

    # NOTE: intentionally not torn down here -- shared account-level singleton that other
    # concurrently-running checks may depend on; deleting it per-check would race with them.
    return role["Arn"]


def _retry_role_propagation(fn, timeout_s: float = 90.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as err:
            if err.response["Error"]["Code"] != "InvalidRoleException" or time.monotonic() >= deadline:
                raise
            time.sleep(5)


def _create_vpc(ctx) -> dict[str, str]:
    ec2 = ctx.client("ec2")
    vpc = ec2.create_vpc(
        CidrBlock="10.221.0.0/24",
        TagSpecifications=[
            {
                "ResourceType": "vpc",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-appstream-vpc-")}],
            }
        ],
    )["Vpc"]
    vpc_id = vpc["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        state = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["State"]
        if state == "available":
            break
        time.sleep(1)

    azs = [
        az["ZoneName"]
        for az in ec2.describe_availability_zones()["AvailabilityZones"]
        if az["State"] == "available"
    ][:2]
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.221.0.{i * 128}/25",
            AvailabilityZone=az,
            TagSpecifications=[
                {
                    "ResourceType": "subnet",
                    "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-appstream-subnet-")}],
                }
            ],
        )["Subnet"]
        subnet_id = subnet["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        subnet_ids.append(subnet_id)
    return {"vpc_id": vpc_id, "subnet_id": subnet_ids[0], "subnet_ids": subnet_ids}


def _visit_streaming_url(ctx, url: str) -> str:
    """Follow the signed StreamingURL as a browser would and return the final URL AppStream's real
    backend redirected to. `HTTPError` still carries a resolved `.url` -- the 404 that terminates
    the redirect chain is expected (see the call site) and is not swallowed here, only reported."""
    import urllib.error
    import urllib.request

    try:
        target_url, route_headers = ctx.endpoint_route(url)
        return urllib.request.urlopen(urllib.request.Request(target_url, headers=route_headers), timeout=20).url
    except urllib.error.HTTPError as exc:
        return exc.url


def _wait_for_fleet_state(ctx, fleet_name: str, target_state: str, timeout_s: float) -> None:
    appstream = ctx.client("appstream")
    deadline = time.monotonic() + timeout_s
    last_state = None
    while time.monotonic() < deadline:
        described = appstream.describe_fleets(Names=[fleet_name])["Fleets"][0]
        last_state = described["State"]
        if last_state == target_state:
            return
        time.sleep(2)
    raise AssertionError(f"fleet never reached {target_state}, last state was {last_state}")


def _delete_fleet_when_stopped(appstream, fleet_name: str, timeout_s: float = 900.0) -> None:
    """Teardown: DeleteFleet is refused while a StopFleet is still in flight, so wait (bounded)
    for the fleet to leave STARTING/STOPPING/RUNNING before deleting it."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        fleets = appstream.describe_fleets(Names=[fleet_name])["Fleets"]
        if fleets[0]["State"] == "STOPPED":
            break
        if fleets[0]["State"] == "RUNNING":
            try:
                appstream.stop_fleet(Name=fleet_name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        time.sleep(10)
    appstream.delete_fleet(Name=fleet_name)


def _error(fn):
    """Call fn(); return the (code, message) of the botocore error it raises. An unexpected
    success raises AssertionError, so an accepted call never reads as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes. A resource in this
# VPC deletes asynchronously, so an immediate DeleteSubnet / DeleteSecurityGroup / DeleteVpc fails
# with DependencyViolation while its ENIs remain: retry that code inside one shared window, then
# raise naming the ENIs still attached.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(10)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if _time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(10)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
