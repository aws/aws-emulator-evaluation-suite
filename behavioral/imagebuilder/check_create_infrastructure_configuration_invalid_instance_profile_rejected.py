"""create-infrastructure-configuration-invalid-instance-profile-rejected."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-infrastructure-configuration-invalid-instance-profile-rejected"
GROUP = "error-semantics"
SERVICES = ["imagebuilder"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateInfrastructureConfiguration with a non-existent instance profile name is rejected."""
    ib = ctx.client("imagebuilder")
    bogus_profile = ctx.unique_name("sim2real-ib-nonexistent-profile-")
    rejected_name = ctx.unique_name("sim2real-ib-infra-")

    code, msg = _error(
        lambda: ib.create_infrastructure_configuration(
            name=rejected_name,
            instanceProfileName=bogus_profile,
            clientToken=str(uuid.uuid4()),
        )
    )
    assert code == "InvalidParameterValueException", f"expected InvalidParameterValueException, got {code!r}"
    expected = (
        "Invalid parameter value for instanceProfileName: The provided instance profile does not exist. "
        "Please specify a different instance profile and try again."
    )
    assert msg == expected, f"expected message {expected!r}, got {msg!r}"

    # effect-absent: the rejected call must not have created anything by that name
    listed = ib.list_infrastructure_configurations(
        filters=[{"name": "name", "values": [rejected_name]}]
    )["infrastructureConfigurationSummaryList"]
    assert listed == [], f"expected no infrastructure configuration named {rejected_name!r}, found {listed!r}"

    # positive control: a real instance profile is accepted
    real_arn = _create_infra_config(ctx)
    got = ib.get_infrastructure_configuration(infrastructureConfigurationArn=real_arn)["infrastructureConfiguration"]
    assert got["arn"] == real_arn


def _error(fn):
    """Call fn(); return its botocore error (Code, Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_instance_profile(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-ib-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.create_instance_profile(
        InstanceProfileName=role_name,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=role_name))
    iam.add_role_to_instance_profile(InstanceProfileName=role_name, RoleName=role_name)
    ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(InstanceProfileName=role_name, RoleName=role_name))
    return role_name


def _create_infra_config(ctx, **extra) -> str:
    ib = ctx.client("imagebuilder")
    profile = _create_instance_profile(ctx)
    name = ctx.unique_name("sim2real-ib-infra-")
    extra.setdefault("tags", {"sim2real": "true"})
    deadline = time.monotonic() + 90.0
    last_exc = None
    while time.monotonic() < deadline:
        try:
            resp = ib.create_infrastructure_configuration(
                name=name, instanceProfileName=profile, clientToken=str(uuid.uuid4()), **extra
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
