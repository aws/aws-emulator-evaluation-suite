"""capacity-provider-name-unicode-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "capacity-provider-name-unicode-rejected"
GROUP = "overly-permissive"
SERVICES = ["lambda"]

_OPERATOR_POLICY_ARN = "arn:aws:iam::aws:policy/AWSLambdaManagedEC2ResourceOperator"
_LAMBDA_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateCapacityProvider rejects a non-ASCII CapacityProviderName (pattern `[a-zA-Z0-9-_]+`)
    with ValidationException, leaving no capacity provider behind, while a same-shaped
    ASCII name still succeeds (positive control)."""
    lam = ctx.client("lambda")
    subnet_id, sg_id = _create_vpc_resources(ctx)
    operator_role_arn = _create_operator_role(ctx)
    bad_name = ctx.unique_name("sim2real-lambda-cp-") + "-東京"

    def _cleanup_bad_name():
        # A name refused by the request pattern cannot name any provider: nothing to delete.
        try:
            lam.delete_capacity_provider(CapacityProviderName=bad_name)
        except ClientError as exc:
            error = exc.response["Error"]
            if error["Code"] == "ValidationException" and error.get("Message") == _name_pattern_message(bad_name):
                return
            if error["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_bad_name)

    code, message = _client_error(
        lambda: lam.create_capacity_provider(
            CapacityProviderName=bad_name,
            VpcConfig={"SubnetIds": [subnet_id], "SecurityGroupIds": [sg_id]},
            PermissionsConfig={"CapacityProviderOperatorRoleArn": operator_role_arn},
            InstanceRequirements={"Architectures": ["x86_64"]},
        )
    )
    # Empirically (real AWS), a non-ASCII CapacityProviderName is rejected by request-shape
    # validation (before any resource-level checks) with ValidationException, not
    # InvalidParameterValueException.
    assert code == "ValidationException", code
    expected_create_message = _name_pattern_message(bad_name)
    assert message == expected_create_message, (
        f"CreateCapacityProvider with a non-ASCII name returned message {message!r}, "
        f"expected {expected_create_message!r}"
    )

    # (a) the effect is absent -- no capacity provider was created under that (rejected) name.
    # Since the name itself fails request-shape validation, GetCapacityProvider on that same
    # literal name is *also* rejected at validation time (ValidationException) rather than
    # reaching the resource-lookup path (ResourceNotFoundException).
    absent_code, absent_message = _client_error(lambda: lam.get_capacity_provider(CapacityProviderName=bad_name))
    assert absent_code == "ValidationException", absent_code
    expected_get_message = _name_pattern_message(bad_name)
    assert absent_message == expected_get_message, (
        f"GetCapacityProvider with the non-ASCII name returned message {absent_message!r}, "
        f"expected {expected_get_message!r}"
    )

    # (b) positive control in the same file: a valid ASCII name still succeeds. A
    # freshly-created operator role can take a few seconds to propagate through IAM before
    # Lambda's cross-service assume-role check will accept it, so retry on that specific
    # transient InvalidParameterValueException.
    good_name = ctx.unique_name("sim2real-lambda-cp-")
    resp = _create_cp_with_role_propagation_retry(
        lam, good_name, subnet_id, sg_id, operator_role_arn
    )
    good_arn = resp["CapacityProvider"]["CapacityProviderArn"]

    def _cleanup():
        deadline = time.monotonic() + 120.0
        while True:
            try:
                lam.delete_capacity_provider(CapacityProviderName=good_name)
                break
            except lam.exceptions.ResourceNotFoundException:
                return
            except lam.exceptions.ResourceConflictException:
                if time.monotonic() > deadline:
                    raise
                time.sleep(2)
        _wait_for_capacity_provider_gone(ctx, good_name, timeout_s=300.0)

    ctx.on_cleanup(_cleanup)

    got = lam.get_capacity_provider(CapacityProviderName=good_name)["CapacityProvider"]
    assert got["CapacityProviderArn"] == good_arn, (
        f"expected GetCapacityProvider to reflect ARN {good_arn!r}, got {got['CapacityProviderArn']!r}"
    )


# ===== helpers =====

_NAME_PATTERN = (
    r"(arn:aws[a-zA-Z-]*:lambda:(eusc-)?[a-z]{2}((-gov)|(-iso([a-z]?)))?-[a-z]+-\d{1}:\d{12}"
    r":capacity-provider:[a-zA-Z0-9-_]+)|[a-zA-Z0-9-_]+"
)


def _name_pattern_message(name):
    return (
        f"1 validation error detected: Value '{name}' at 'capacityProviderName' failed to satisfy "
        f"constraint: Member must satisfy regular expression pattern: {_NAME_PATTERN}"
    )

def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises, so that
    accepting input AWS refuses is reported as an acceptance, not as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_cp_with_role_propagation_retry(lam, name, subnet_id, sg_id, operator_role_arn, timeout_s=180.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return lam.create_capacity_provider(
                CapacityProviderName=name,
                VpcConfig={"SubnetIds": [subnet_id], "SecurityGroupIds": [sg_id]},
                PermissionsConfig={"CapacityProviderOperatorRoleArn": operator_role_arn},
                InstanceRequirements={"Architectures": ["x86_64"]},
            )
        except lam.exceptions.InvalidParameterValueException:
            if time.monotonic() > deadline:
                raise
            time.sleep(2)


def _create_vpc_resources(ctx):
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-lambda-cp-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.79.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.79.1.0/24",
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))
    sg_id = ec2.create_security_group(
        GroupName=name,
        Description="sim2real lambda managed-instances capacity provider sg",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": name}]}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id))
    return subnet_id, sg_id


def _create_operator_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-lambda-cpop-")
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_LAMBDA_TRUST_POLICY)["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_OPERATOR_POLICY_ARN)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_OPERATOR_POLICY_ARN))
    return role_arn


def _wait_for_capacity_provider_gone(ctx, name, timeout_s=900.0):
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            lam.get_capacity_provider(CapacityProviderName=name)
        except lam.exceptions.ResourceNotFoundException:
            return
        time.sleep(2)
    raise AssertionError(f"capacity provider {name} was not deleted within {timeout_s}s")


# Network deletes wait, in one bounded window shared by the check's network deletes, for the
# AWS-managed ENIs of asynchronously deleted resources to leave, retry DependencyViolation inside
# it, and raise naming the ENIs still attached; every other error propagates.
_NET_TEARDOWN_S = 450.0
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
