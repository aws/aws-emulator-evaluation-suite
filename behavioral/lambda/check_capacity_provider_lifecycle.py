"""capacity-provider-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "capacity-provider-lifecycle"
GROUP = "state-machine"
SERVICES = ["lambda"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Capacity provider transitions create->active->updated->deleted->404-on-get."""
    lam = ctx.client("lambda")
    name, cp_arn = _create_capacity_provider(ctx)

    active = _poll_until(
        lambda: lam.get_capacity_provider(CapacityProviderName=name)["CapacityProvider"],
        lambda cp: cp["State"] in ("Active", "Failed"),
        timeout_s=240.0,
        interval_s=5.0,
    )
    assert active["State"] == "Active", f"capacity provider entered {active['State']} instead of Active"

    updated = lam.update_capacity_provider(
        CapacityProviderName=name,
        CapacityProviderScalingConfig={"MaxVCpuCount": 32},
    )["CapacityProvider"]
    assert updated["CapacityProviderScalingConfig"]["MaxVCpuCount"] == 32, (
        f"UpdateCapacityProvider's own response reported MaxVCpuCount="
        f"{updated['CapacityProviderScalingConfig'].get('MaxVCpuCount')!r}, expected 32"
    )

    settled = _poll_until(
        lambda: lam.get_capacity_provider(CapacityProviderName=name)["CapacityProvider"],
        lambda cp: cp["State"] in ("Active", "Failed"),
        timeout_s=120.0,
        interval_s=5.0,
    )
    settled_max = settled["CapacityProviderScalingConfig"]["MaxVCpuCount"]
    assert settled_max == 32, (
        f"an independent GetCapacityProvider read after the update settled shows "
        f"MaxVCpuCount={settled_max!r}, expected the updated value 32"
    )

    lam.delete_capacity_provider(CapacityProviderName=name)

    def _get_after_delete():
        return _client_error(lambda: lam.get_capacity_provider(CapacityProviderName=name))

    def _gone_or_none():
        # the provider keeps reading back while its deletion is in progress
        try:
            lam.get_capacity_provider(CapacityProviderName=name)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message")
        return None

    not_found_message = (
        f"Capacity provider not found: {cp_arn}. Check that the ARN is correct and the "
        f"capacity provider exists in this Region."
    )
    final_code, final_message = _poll_until(
        _gone_or_none,
        lambda got: got is not None,
        timeout_s=900.0,
        interval_s=10.0,
    )
    assert final_code == "ResourceNotFoundException", (
        f"GetCapacityProvider after delete returned error code {final_code!r}, "
        f"expected ResourceNotFoundException"
    )
    assert final_message == not_found_message, (
        f"GetCapacityProvider after delete returned message {final_message!r}, "
        f"expected {not_found_message!r}"
    )

    update_after_delete_code, update_after_delete_message = _client_error(
        lambda: lam.update_capacity_provider(
            CapacityProviderName=name,
            CapacityProviderScalingConfig={"MaxVCpuCount": 16},
        )
    )
    assert update_after_delete_code == "ResourceNotFoundException", (
        f"UpdateCapacityProvider on a deleted capacity provider returned error code "
        f"{update_after_delete_code!r}, expected ResourceNotFoundException -- a mutation "
        f"on the dead id must fail the same way the read does"
    )
    assert update_after_delete_message == not_found_message, (
        f"UpdateCapacityProvider on a deleted capacity provider returned message "
        f"{update_after_delete_message!r}, expected {not_found_message!r}"
    )

    still_gone_code, still_gone_message = _get_after_delete()
    assert still_gone_message == not_found_message, (
        f"GetCapacityProvider after the rejected update returned message {still_gone_message!r}, "
        f"expected {not_found_message!r}"
    )
    assert still_gone_code == "ResourceNotFoundException", (
        f"an independent GetCapacityProvider read after the rejected UpdateCapacityProvider "
        f"attempt returned {still_gone_code!r}, expected ResourceNotFoundException -- the "
        f"rejected mutation must not have resurrected or altered the deleted provider"
    )


# ===== helpers =====
def _client_error(call):
    """Run a call that MUST be refused and return its (code, message). An unexpected success
    raises, so an over-permissive target is reported as accepting, not as a code mismatch."""
    try:
        result = call()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_capacity_provider(ctx):
    """Build VPC/IAM prerequisites and create a capacity provider, skipping if the
    Lambda Managed Instances feature or its prerequisites are unavailable."""
    from botocore.exceptions import ClientError

    lam = ctx.client("lambda")
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")

    try:
        net_name = ctx.unique_name("sim2real-behav-cpnet-")
        vpc_id = ec2.create_vpc(
            CidrBlock="10.81.0.0/16",
            TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": net_name}]}],
        )["Vpc"]["VpcId"]
        ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock="10.81.1.0/24",
            TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": net_name}]}],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))
        subnet_ids = [subnet_id]

        sg_name = ctx.unique_name("sim2real-behav-cpsg-")
        sg = ec2.create_security_group(
            GroupName=sg_name,
            Description="sim2real capacity provider behavioral check",
            VpcId=vpc_id,
            TagSpecifications=[
                {"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": sg_name}]}
            ],
        )
        sg_id = sg["GroupId"]
        ctx.on_cleanup(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id))

        role_name = ctx.unique_name("sim2real-behav-cprole-")
        trust = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
        role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
        ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
        policy_arn = "arn:aws:iam::aws:policy/AmazonEC2FullAccess"
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
        operator_role_arn = role["Role"]["Arn"]

        cp_name = ctx.unique_name("sim2real-behav-cp-")

        def _try_create():
            try:
                return lam.create_capacity_provider(
                    CapacityProviderName=cp_name,
                    VpcConfig={"SubnetIds": subnet_ids, "SecurityGroupIds": [sg_id]},
                    PermissionsConfig={"CapacityProviderOperatorRoleArn": operator_role_arn},
                    InstanceRequirements={"Architectures": ["x86_64"]},
                    CapacityProviderScalingConfig={"MaxVCpuCount": 16},
                )["CapacityProvider"]
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") == "InvalidParameterValueException":
                    return None  # operator role not yet propagated to the EC2/IAM control plane
                raise

        resp = _poll_until(_try_create, lambda cp: cp is not None, timeout_s=120.0, interval_s=5.0)
    except AssertionError:
        raise
    except Exception as e:  # noqa: BLE001 - infra/feature availability is a prerequisite, not a bug
        raise AssertionError(f"Lambda capacity provider prerequisites unavailable: {e}") from e

    ctx.on_cleanup(lambda: _delete_cp(lam, cp_name))
    return cp_name, resp["CapacityProviderArn"]


def _delete_cp(lam, name: str) -> None:
    """Delete, retrying ResourceConflictException (still settling) every 2 s for up to 120 s."""
    deadline = time.monotonic() + 120
    while True:
        try:
            lam.delete_capacity_provider(CapacityProviderName=name)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceConflictException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


# Network deletes wait, in one bounded window shared by the check's network deletes, for the
# AWS-managed ENIs of asynchronously deleted resources to leave, retry DependencyViolation inside
# it, and raise naming the ENIs still attached; every other error propagates.
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
