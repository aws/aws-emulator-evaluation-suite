"""deploy-ses-configuration-set-cfn-usable."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "deploy-ses-configuration-set-cfn-usable"
GROUP = "deploy"
SERVICES = ["ses"]

_TEMPLATE_BODY = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  ConfigSetNameParam:
    Type: String
Resources:
  ConfigSet:
    Type: AWS::SES::ConfigurationSet
    Properties:
      Name: !Ref ConfigSetNameParam
"""


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation-deployed AWS::SES::ConfigurationSet is describable via SES v1, its v1
    sending toggle shows in SESv2 SendingOptions, and deleting the stack removes the set."""
    ses = ctx.client("ses")
    sesv2 = ctx.client("sesv2")
    cfn = ctx.client("cloudformation")
    cs_name = ctx.unique_name("sim2real-ses-cfncs-")
    stack_name = _deploy_cfn(ctx, _TEMPLATE_BODY, {"ConfigSetNameParam": cs_name})

    desc = ses.describe_configuration_set(ConfigurationSetName=cs_name)
    assert desc["ConfigurationSet"]["Name"] == cs_name, (
        f"expected CloudFormation-deployed ConfigurationSet named {cs_name!r}, "
        f"got {desc['ConfigurationSet'].get('Name')!r}"
    )

    sending0 = sesv2.get_configuration_set(ConfigurationSetName=cs_name)["SendingOptions"]
    assert sending0["SendingEnabled"] is True, (
        f"expected SendingEnabled True right after deploy, got {sending0['SendingEnabled']!r}"
    )

    ses.update_configuration_set_sending_enabled(
        ConfigurationSetName=cs_name, Enabled=False
    )
    sending1 = sesv2.get_configuration_set(ConfigurationSetName=cs_name)["SendingOptions"]
    assert sending1["SendingEnabled"] is False, (
        f"expected SendingEnabled False after disabling sending, got {sending1['SendingEnabled']!r}"
    )

    ses.update_configuration_set_sending_enabled(
        ConfigurationSetName=cs_name, Enabled=True
    )
    sending2 = sesv2.get_configuration_set(ConfigurationSetName=cs_name)["SendingOptions"]
    assert sending2["SendingEnabled"] is True, (
        f"expected SendingEnabled True after re-enabling sending, got {sending2['SendingEnabled']!r}"
    )

    _delete_stack_and_wait(cfn, stack_name)
    try:
        sesv2.get_configuration_set(ConfigurationSetName=cs_name)
        raise AssertionError(
            f"expected {cs_name!r} to be gone after its CloudFormation stack was "
            "deleted, but get_configuration_set still returned it"
        )
    except sesv2.exceptions.NotFoundException as exc:
        message = exc.response["Error"].get("Message")
        expected = f"Configuration set <{cs_name}> does not exist."
        assert message == expected, f"expected {expected!r}, got {message!r}"


def _deploy_cfn(ctx: Any, template_body: str, parameters: dict[str, str]) -> str:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-ses-stack-")

    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack_name))
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Parameters=[
            {"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()
        ],
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:check", "Value": CHECK}],
    )
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )
    return stack_name


def _delete_stack_and_wait(cfn: Any, stack_name: str) -> None:
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
