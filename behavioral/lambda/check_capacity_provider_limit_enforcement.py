"""capacity-provider-limit-enforcement."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError


from behavioral_harness import tags


CHECK = "capacity-provider-limit-enforcement"
GROUP = 'compute'
SERVICES = ['lambda']


def _ensure_operator_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-cp-op-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Path="/sim2real/",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]

    def _cleanup():
        try:
            iam.detach_role_policy(
                RoleName=role_name,
                PolicyArn="arn:aws:iam::aws:policy/AWSLambdaManagedEC2ResourceOperator",
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    try:
        iam.attach_role_policy(
            RoleName=role_name,
            PolicyArn="arn:aws:iam::aws:policy/AWSLambdaManagedEC2ResourceOperator",
        )
    except ClientError:
        pass
    return arn


def _ensure_network(ctx):
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(CidrBlock="10.77.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.77.1.0/24")["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))
    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-behav-cp-sg-"),
        Description="sim2real-behav capacity provider sg", VpcId=vpc_id,
    )["GroupId"]
    ctx.on_cleanup(lambda: ec2.delete_security_group(GroupId=sg_id))
    return subnet_id, sg_id


def _create_capacity_provider(ctx, lam, name):
    subnet_id, sg_id = _ensure_network(ctx)
    operator_role_arn = _ensure_operator_role(ctx)
    params = dict(
        CapacityProviderName=name,
        VpcConfig={"SubnetIds": [subnet_id], "SecurityGroupIds": [sg_id]},
        PermissionsConfig={"CapacityProviderOperatorRoleArn": operator_role_arn},
        InstanceRequirements={"Architectures": ["x86_64"]},
    )
    deadline = time.monotonic() + 60
    last_exc = None
    while time.monotonic() < deadline:
        try:
            resp = lam.create_capacity_provider(**params)
            break
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InvalidParameterValueException":
                last_exc = exc
                time.sleep(3.0)
                continue
            raise
    else:
        raise last_exc

    def _cleanup_cp():
        d = time.monotonic() + 120
        while True:
            try:
                lam.delete_capacity_provider(CapacityProviderName=name)
                return
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code == "ResourceNotFoundException":
                    return
                if code != "ResourceConflictException" or time.monotonic() >= d:
                    raise
            time.sleep(2)

    ctx.on_cleanup(_cleanup_cp)
    return resp


def _await_settled(lam, name):
    deadline = time.monotonic() + 120
    last_state = None
    while time.monotonic() < deadline:
        resp = lam.get_capacity_provider(CapacityProviderName=name)
        cp = resp["CapacityProvider"]
        last_state = cp.get("State")
        if last_state in ("Active", "Failed"):
            return cp
        time.sleep(5.0)
    raise AssertionError(
        f"capacity provider {name} did not leave Pending within 120s (last state {last_state})"
    )


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateCapacityProvider succeeds and GetCapacityProvider reports it Active with the requested
    VPC and permissions config. The 1,000/account limit is too large to exhaust, so
    CapacityProviderLimitExceededException is not exercised.
    """
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-behav-cp-")
    try:
        created = _create_capacity_provider(ctx, lam, name)
    except ClientError as exc:
        raise AssertionError(f"CreateCapacityProvider not usable in this account/region: {exc}") from exc
    cp = created["CapacityProvider"]
    cp_arn = cp["CapacityProviderArn"]
    assert cp_arn.endswith(f":capacity-provider:{name}"), cp_arn

    fetched = _await_settled(lam, name)
    assert fetched["CapacityProviderArn"] == cp_arn, (fetched["CapacityProviderArn"], cp_arn)
    assert fetched["State"] == "Active", f"expected Active, got {fetched['State']}"
    assert sorted(fetched["VpcConfig"]["SubnetIds"]) == sorted(cp["VpcConfig"]["SubnetIds"]), (
        fetched["VpcConfig"]["SubnetIds"], cp["VpcConfig"]["SubnetIds"]
    )
    assert sorted(fetched["VpcConfig"]["SecurityGroupIds"]) == sorted(cp["VpcConfig"]["SecurityGroupIds"]), (
        fetched["VpcConfig"]["SecurityGroupIds"], cp["VpcConfig"]["SecurityGroupIds"]
    )
    fetched_role = fetched["PermissionsConfig"]["CapacityProviderOperatorRoleArn"]
    created_role = cp["PermissionsConfig"]["CapacityProviderOperatorRoleArn"]
    assert fetched_role == created_role, (fetched_role, created_role)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
