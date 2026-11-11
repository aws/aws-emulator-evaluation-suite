"""create-infrastructure-configuration-duplicate-name-rejected."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-infrastructure-configuration-duplicate-name-rejected"
GROUP = "overly-permissive"
SERVICES = ["imagebuilder"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Creating an infrastructure configuration with a name that already exists is rejected, and the original is left unmodified."""
    ib = ctx.client("imagebuilder")
    profile_name = _create_instance_profile(ctx)

    config_name = ctx.unique_name("sim2real-ib-infra-")
    arn = _create_infra_config_with_retry(ctx, ib, config_name, profile_name, description="original")
    ctx.on_cleanup(lambda: ib.delete_infrastructure_configuration(infrastructureConfigurationArn=arn))

    code, msg = _error(
        lambda: ib.create_infrastructure_configuration(
            name=config_name,
            instanceProfileName=profile_name,
            description="duplicate attempt",
            clientToken=str(uuid.uuid4()),
        )
    )
    assert code == "ResourceAlreadyExistsException", f"expected ResourceAlreadyExistsException, got {code!r}"
    assert msg == "The resource already exists.", f"expected message 'The resource already exists.', got {msg!r}"

    # effect absent: the original configuration's description was not overwritten
    got = ib.get_infrastructure_configuration(infrastructureConfigurationArn=arn)["infrastructureConfiguration"]
    assert got["description"] == "original", f"expected description 'original', got {got['description']!r}"

    # effect absent: the rejected duplicate did not register a second configuration
    # under this name — an independent read at the destination, not the mutating
    # call's own response.
    found = ib.list_infrastructure_configurations(filters=[{"name": "name", "values": [config_name]}])[
        "infrastructureConfigurationSummaryList"
    ]
    assert len(found) == 1, f"expected exactly one configuration named {config_name!r}, found {len(found)}"
    assert found[0]["arn"] == arn, f"expected {arn!r}, found {found[0]['arn']!r}"

    # positive control: a distinctly-named configuration still succeeds
    control_name = ctx.unique_name("sim2real-ib-infra-control-")
    control_arn = _create_infra_config_with_retry(ctx, ib, control_name, profile_name)
    ctx.on_cleanup(lambda: ib.delete_infrastructure_configuration(infrastructureConfigurationArn=control_arn))
    control = ib.get_infrastructure_configuration(infrastructureConfigurationArn=control_arn)["infrastructureConfiguration"]
    assert control["name"] == control_name, f"expected {control_name!r}, got {control['name']!r}"


def _error(fn):
    """Call fn(); return its botocore error (Code, Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_instance_profile(ctx):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-ib-profile-")
    trust = (
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
        '"Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
    )
    iam.create_role(RoleName=name, AssumeRolePolicyDocument=trust)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.create_instance_profile(InstanceProfileName=name)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=name))
    iam.add_role_to_instance_profile(InstanceProfileName=name, RoleName=name)
    ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(InstanceProfileName=name, RoleName=name))
    return name


def _create_infra_config_with_retry(ctx, ib, name, profile_name, description=None, timeout_s=90.0):
    # a freshly created IAM instance profile can take a short while to propagate;
    # poll the actual create call rather than sleeping a fixed duration.
    deadline = time.monotonic() + timeout_s
    last_exc = None
    kwargs = dict(name=name, instanceProfileName=profile_name, clientToken=str(uuid.uuid4()))
    if description:
        kwargs["description"] = description
    while time.monotonic() < deadline:
        try:
            return ib.create_infrastructure_configuration(**kwargs)["infrastructureConfigurationArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("InvalidRequestException", "InvalidParameterValueException"):
                raise
            last_exc = exc
            time.sleep(3)
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
