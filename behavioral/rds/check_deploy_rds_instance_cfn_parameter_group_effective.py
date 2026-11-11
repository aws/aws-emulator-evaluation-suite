"""deploy-rds-instance-cfn-parameter-group-effective."""
from __future__ import annotations

import secrets
import string


from behavioral_harness import tags

CHECK = "deploy-rds-instance-cfn-parameter-group-effective"
GROUP = "deploy"
SERVICES = ["rds"]

_TEMPLATE = """
Parameters:
  EngineVersion:
    Type: String
  ParamGroupFamily:
    Type: String
  MasterUserPassword:
    Type: String
    NoEcho: true
Resources:
  ParamGroup:
    Type: AWS::RDS::DBParameterGroup
    Properties:
      Family: !Ref ParamGroupFamily
      Description: sim2real behavioral non-default parameter group
      Parameters:
        innodb_lock_wait_timeout: "120"
  Instance:
    Type: AWS::RDS::DBInstance
    DeletionPolicy: Delete
    Properties:
      Engine: mysql
      EngineVersion: !Ref EngineVersion
      DBInstanceClass: db.t3.micro
      AllocatedStorage: 20
      MasterUsername: s2radmin
      MasterUserPassword: !Ref MasterUserPassword
      DBParameterGroupName: !Ref ParamGroup
      PubliclyAccessible: false
Outputs:
  InstanceId:
    Value: !Ref Instance
  ParamGroupName:
    Value: !Ref ParamGroup
"""


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CFN-deployed MySQL DBInstance lists the stack's custom DBParameterGroup, and
    DescribeDBParameters reports innodb_lock_wait_timeout=120 as a user override; the running
    engine's value is not read."""
    rds = ctx.client("rds")
    engine_versions = rds.describe_db_engine_versions(Engine="mysql", DefaultOnly=True)[
        "DBEngineVersions"
    ]
    if not engine_versions:
        raise AssertionError("no default mysql engine version reported by describe-db-engine-versions")
    ev = engine_versions[0]
    engine_version = ev["EngineVersion"]
    family = ev["DBParameterGroupFamily"]

    password = _rand_password()
    stack_name = _deploy_cfn(
        ctx,
        _TEMPLATE,
        parameters=[
            {"ParameterKey": "EngineVersion", "ParameterValue": engine_version},
            {"ParameterKey": "ParamGroupFamily", "ParameterValue": family},
            {"ParameterKey": "MasterUserPassword", "ParameterValue": password},
        ],
        timeout_s=1800,
    )
    outputs = _stack_outputs(ctx, stack_name)
    instance_id = outputs["InstanceId"]
    param_group_name = outputs["ParamGroupName"]

    instance = rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]
    assert instance["DBInstanceStatus"] == "available", (
        f"expected DBInstanceStatus 'available' after stack create, got "
        f"{instance['DBInstanceStatus']!r}"
    )
    groups = {g["DBParameterGroupName"]: g for g in instance["DBParameterGroups"]}
    assert param_group_name in groups, f"instance not attached to {param_group_name}: {groups}"

    params = rds.describe_db_parameters(DBParameterGroupName=param_group_name, Source="user")[
        "Parameters"
    ]
    by_name = {p["ParameterName"]: p for p in params}
    assert "innodb_lock_wait_timeout" in by_name, "custom parameter not present as a user override"
    actual_value = by_name["innodb_lock_wait_timeout"]["ParameterValue"]
    assert actual_value == "120", (
        f"expected innodb_lock_wait_timeout=120 in effect on {param_group_name}, got {actual_value!r}"
    )


# ===== helpers =====
def _rand_password() -> str:
    alphabet = string.ascii_letters + string.digits
    return "Aa1" + "".join(secrets.choice(alphabet) for _ in range(16))


def _deploy_cfn(ctx, template_body, parameters=None, timeout_s=1800) -> str:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-rds-cfn-")

    def _cleanup():
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 750}
        )

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Parameters=parameters or [],
        OnFailure="DELETE",
    )
    ctx.on_cleanup(_cleanup)
    max_attempts = max(int(timeout_s // 30), 10)
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": max_attempts * 30 // 2}
    )
    return stack_name


def _stack_outputs(ctx, stack_name) -> dict[str, str]:
    cfn = ctx.client("cloudformation")
    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
