"""create-infrastructure-configuration-get-roundtrip."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-infrastructure-configuration-get-roundtrip"
GROUP = "crud-roundtrip"
SERVICES = ["imagebuilder"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateInfrastructureConfiguration persists the instance profile binding, visible via Get."""
    ib = ctx.client("imagebuilder")
    profile = _create_instance_profile(ctx)
    name = ctx.unique_name("sim2real-ib-infra-")
    arn = _create_infra_config_with_retry(ctx, name, profile)

    got = ib.get_infrastructure_configuration(infrastructureConfigurationArn=arn)["infrastructureConfiguration"]
    assert got["name"] == name, f"expected name {name!r}, got {got['name']!r}"
    assert got["instanceProfileName"] == profile, (
        f"expected instanceProfileName {profile!r}, got {got['instanceProfileName']!r}"
    )
    assert got["arn"] == arn, f"expected arn {arn!r}, got {got['arn']!r}"


def _create_instance_profile(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-ib-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    iam_tags = [{"Key": "sim2real", "Value": "true"}]
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=iam_tags)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.create_instance_profile(InstanceProfileName=role_name, Tags=iam_tags)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=role_name))
    iam.add_role_to_instance_profile(InstanceProfileName=role_name, RoleName=role_name)
    ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(InstanceProfileName=role_name, RoleName=role_name))
    return role_name


def _create_infra_config_with_retry(ctx, name: str, profile: str, **extra) -> str:
    ib = ctx.client("imagebuilder")
    deadline = time.monotonic() + 90.0
    last_exc = None
    while time.monotonic() < deadline:
        try:
            resp = ib.create_infrastructure_configuration(
                name=name,
                instanceProfileName=profile,
                clientToken=str(uuid.uuid4()),
                tags={"sim2real": "true"},
                **extra,
            )
            break
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("InvalidParameterValueException", "InvalidRequestException"):
                last_exc = e
                time.sleep(5)
                continue
            raise
    else:
        raise last_exc
    arn = resp["infrastructureConfigurationArn"]
    ctx.on_cleanup(lambda: ib.delete_infrastructure_configuration(infrastructureConfigurationArn=arn))
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
