"""launch-constraint-role-governs-plan-execution."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "launch-constraint-role-governs-plan-execution"
GROUP = 'provisioning'
SERVICES = ["servicecatalog"]


_TEMPLATE = {
    "AWSTemplateFormatVersion": "2010-09-09",
    "Parameters": {"Env": {"Type": "String", "AllowedValues": ["dev", "prod"], "Default": "dev"}},
    "Resources": {"Marker": {"Type": "AWS::CloudFormation::WaitConditionHandle"}},
    "Outputs": {"EnvEcho": {"Value": {"Ref": "Env"}}},
}


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        for obj in page.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket)


def _host_template(ctx, s3) -> str:
    """Publish the product template to a bucket this check owns."""
    bucket = ctx.unique_name("sim2real-sc-tpl-")
    kw = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kw["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kw)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_object(Bucket=bucket, Key="product.json", Body=json.dumps(_TEMPLATE).encode())
    return ctx.s3_object_url(f"https://s3.{ctx.region}.amazonaws.com/{bucket}/product.json", bucket, "product.json")


_SESSION_NAME = "sim2real-sc-session"


def _assumed_role(ctx, iam, sts, account: str, name_prefix: str, trust_principal: dict,
                   policy: dict) -> tuple:
    """A fresh role with the given trust and inline policy.

    Returns (role_arn, assumed_creds_or_None, session_arn_or_None). When ``trust_principal``
    allows this account's root to assume it, also assumes it; otherwise the last two are None
    (a service-trusted role no check caller needs to assume itself).
    """
    role_name = ctx.unique_name(name_prefix)[:64]
    trust = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": trust_principal, "Action": "sts:AssumeRole"}]}
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(RoleName=role_name, PolicyName="sim2real-sc-policy",
                         PolicyDocument=json.dumps(policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-sc-policy"))
    if "AWS" not in trust_principal:
        return role_arn, None, None
    end = time.time() + 60.0
    while True:
        try:
            creds = sts.assume_role(RoleArn=role_arn, RoleSessionName=_SESSION_NAME)["Credentials"]
            break
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "AccessDenied" or time.time() > end:
                raise
            time.sleep(3)
    session_arn = f"arn:aws:sts::{account}:assumed-role/{role_name}/{_SESSION_NAME}"
    return role_arn, creds, session_arn


def _await_paths(sc, product_id: str, deadline: float) -> list:
    end = time.time() + deadline
    while True:
        try:
            paths = sc.list_launch_paths(ProductId=product_id).get("LaunchPathSummaries", [])
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise
            paths = []
        if paths:
            return paths
        assert time.time() < end, f"no launch path resolved for {product_id!r} within {deadline}s"
        time.sleep(3)


def _await_plan(sc, plan_id: str, deadline: float) -> dict:
    end = time.time() + deadline
    while True:
        detail = sc.describe_provisioned_product_plan(PlanId=plan_id)
        status = detail["ProvisionedProductPlanDetails"]["Status"]
        if status not in ("CREATE_IN_PROGRESS",):
            return detail
        assert time.time() < end, f"plan {plan_id!r} was still {status!r} after {deadline}s"
        time.sleep(5)


def _await_settled(sc, pp_id: str, deadline: float) -> dict:
    end = time.time() + deadline
    while True:
        detail = sc.describe_provisioned_product(Id=pp_id)["ProvisionedProductDetail"]
        if detail["Status"] not in ("UNDER_CHANGE", "PLAN_IN_PROGRESS"):
            return detail
        assert time.time() < end, f"provisioned product {pp_id!r} was still {detail['Status']!r} after {deadline}s"
        time.sleep(5)


def _terminate(sc, pp_id: str) -> None:
    try:
        sc.terminate_provisioned_product(
            ProvisionedProductId=pp_id, TerminateToken=uuid.uuid4().hex, IgnoreErrors=True)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise
    end = time.time() + 300.0
    while time.time() < end:
        try:
            sc.describe_provisioned_product(Id=pp_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return
            raise
        time.sleep(5)


@tags("axis:happy-path", "concern:deploy", "concern:data-plane", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """A LAUNCH constraint's role, not the caller's own permissions, performs the plan's
    CloudFormation deploy, and nothing is created before ExecuteProvisionedProductPlan runs.
    """
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    sc_admin = ctx.client("servicecatalog")
    s3 = ctx.client("s3")
    cfn = ctx.client("cloudformation")
    account = sts.get_caller_identity()["Account"]

    # The provisioning caller: servicecatalog only, deliberately NO cloudformation permission.
    caller_policy = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": "servicecatalog:*", "Resource": "*"},
        {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}
    caller_arn, caller_creds, caller_session_arn = _assumed_role(
        ctx, iam, sts, account, "sim2real-sc-caller-",
        {"AWS": f"arn:aws:iam::{account}:root"}, caller_policy)
    sc = ctx.client("servicecatalog", creds={
        "aws_access_key_id": caller_creds["AccessKeyId"],
        "aws_secret_access_key": caller_creds["SecretAccessKey"],
        "aws_session_token": caller_creds["SessionToken"]})
    end = time.time() + 60.0
    while True:
        try:
            sc.list_portfolios()
            break
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in ("AccessDeniedException", "AccessDenied") \
                    or time.time() > end:
                raise
            time.sleep(3)

    # The launch role: trusted by Service Catalog, holds the CloudFormation permission instead.
    launch_policy = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": "cloudformation:*", "Resource": "*"},
        {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}
    launch_role_arn, _, _ = _assumed_role(
        ctx, iam, sts, account, "sim2real-sc-launch-",
        {"Service": "servicecatalog.amazonaws.com"}, launch_policy)

    url = _host_template(ctx, s3)
    product = sc_admin.create_product(
        Name=ctx.unique_name("sim2real-sc-prod-"), Owner="sim2real",
        Description="sim2real service-catalog behavioral check",
        ProductType="CLOUD_FORMATION_TEMPLATE", IdempotencyToken=uuid.uuid4().hex,
        ProvisioningArtifactParameters={"Name": "v1", "Type": "CLOUD_FORMATION_TEMPLATE",
                                        "Info": {"LoadTemplateFromURL": url}},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    product_id = product["ProductViewDetail"]["ProductViewSummary"]["ProductId"]
    artifact_id = product["ProvisioningArtifactDetail"]["Id"]
    ctx.on_cleanup(lambda: sc_admin.delete_product(Id=product_id))

    portfolio_id = sc_admin.create_portfolio(
        DisplayName=ctx.unique_name("sim2real-sc-pf-"), ProviderName="sim2real",
        IdempotencyToken=uuid.uuid4().hex, Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["PortfolioDetail"]["Id"]
    ctx.on_cleanup(lambda: sc_admin.delete_portfolio(Id=portfolio_id))

    sc_admin.associate_product_with_portfolio(ProductId=product_id, PortfolioId=portfolio_id)
    ctx.on_cleanup(lambda: sc_admin.disassociate_product_from_portfolio(
        ProductId=product_id, PortfolioId=portfolio_id))
    sc_admin.associate_principal_with_portfolio(
        PortfolioId=portfolio_id, PrincipalARN=caller_arn, PrincipalType="IAM")
    ctx.on_cleanup(lambda: sc_admin.disassociate_principal_from_portfolio(
        PortfolioId=portfolio_id, PrincipalARN=caller_arn))

    # CreateConstraint verifies Service Catalog can assume the launch role at creation time;
    # a role's trust policy takes a few seconds to propagate after CreateRole.
    end = time.time() + 60.0
    while True:
        try:
            constraint = sc_admin.create_constraint(
                PortfolioId=portfolio_id, ProductId=product_id, Type="LAUNCH",
                Parameters=json.dumps({"RoleArn": launch_role_arn}),
                IdempotencyToken=uuid.uuid4().hex)
            break
        except ClientError as exc:
            msg = exc.response.get("Error", {}).get("Message", "")
            if "Access denied while assuming the role" not in msg or time.time() > end:
                raise
            time.sleep(3)
    constraint_id = constraint["ConstraintDetail"]["ConstraintId"]
    ctx.on_cleanup(lambda: sc_admin.delete_constraint(Id=constraint_id))
    assert constraint["ConstraintDetail"]["Type"] == "LAUNCH", (
        f"CreateConstraint reported type {constraint['ConstraintDetail']['Type']!r}, expected 'LAUNCH'"
    )
    described = sc_admin.describe_constraint(Id=constraint_id)
    assert described["ConstraintDetail"]["ConstraintId"] == constraint_id, (
        f"DescribeConstraint returned a different constraint: "
        f"{described['ConstraintDetail']['ConstraintId']!r} != {constraint_id!r}"
    )
    assert json.loads(described["ConstraintParameters"]) == {"RoleArn": launch_role_arn}, (
        f"DescribeConstraint's parameters are {described['ConstraintParameters']!r}, "
        f"expected the launch role {launch_role_arn!r}"
    )

    path_id = _await_paths(sc, product_id, deadline=120.0)[0]["Id"]
    params = sc.describe_provisioning_parameters(
        ProductId=product_id, ProvisioningArtifactId=artifact_id, PathId=path_id)
    env_param = next(p for p in params["ProvisioningArtifactParameters"] if p["ParameterKey"] == "Env")
    assert env_param["DefaultValue"] == "dev", (
        f"DescribeProvisioningParameters reported Env's default as {env_param['DefaultValue']!r}, "
        f"expected 'dev' from the template"
    )

    plan_name = ctx.unique_name("sim2real-sc-plan-")
    pp_name = ctx.unique_name("sim2real-sc-pp-")
    plan = sc.create_provisioned_product_plan(
        PlanName=plan_name, PlanType="CLOUDFORMATION", PathId=path_id, ProductId=product_id,
        ProvisionedProductName=pp_name, ProvisioningArtifactId=artifact_id,
        ProvisioningParameters=[{"Key": "Env", "Value": "prod"}],
        IdempotencyToken=uuid.uuid4().hex)
    plan_id = plan["PlanId"]
    pp_id = plan["ProvisionProductId"]
    ctx.on_cleanup(lambda: _terminate(sc, pp_id))

    plan_detail = _await_plan(sc, plan_id, deadline=180.0)
    status = plan_detail["ProvisionedProductPlanDetails"]["Status"]
    assert status == "CREATE_SUCCESS", (
        f"the plan settled at {status!r} "
        f"({plan_detail['ProvisionedProductPlanDetails'].get('StatusMessage')!r}), expected 'CREATE_SUCCESS'"
    )
    changes = plan_detail.get("ResourceChanges", [])
    marker_change = next((c for c in changes if c.get("LogicalResourceId") == "Marker"), None)
    assert marker_change is not None, f"the plan's ResourceChanges {changes!r} named no 'Marker' change"
    assert marker_change["Action"] == "Add", (
        f"the plan's change for 'Marker' is {marker_change['Action']!r}, expected 'Add'"
    )

    # ---- the invariant: nothing exists yet, before Execute ----
    pre_exec = sc.describe_provisioned_product(Id=pp_id)["ProvisionedProductDetail"]
    assert pre_exec["Status"] == "PLAN_IN_PROGRESS", (
        f"before Execute, the provisioned product is {pre_exec['Status']!r}, expected 'PLAN_IN_PROGRESS'"
    )
    code, pre_exec_msg = None, None
    try:
        sc.get_provisioned_product_outputs(ProvisionedProductId=pp_id)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        pre_exec_msg = exc.response.get("Error", {}).get("Message")
    assert code == "InvalidParametersException", (
        f"before Execute, GetProvisionedProductOutputs answered {code!r} ({pre_exec_msg!r}), "
        f"expected 'InvalidParametersException' because no stack has ever successfully provisioned yet"
    )
    assert pre_exec_msg == "Last Successful Provisioning Record doesn't exist.", (
        f"before Execute, GetProvisionedProductOutputs's message was {pre_exec_msg!r}"
    )

    record = sc.execute_provisioned_product_plan(
        PlanId=plan_id, IdempotencyToken=uuid.uuid4().hex)["RecordDetail"]
    record_id = record["RecordId"]

    detail = _await_settled(sc, pp_id, deadline=240.0)
    assert detail["Status"] == "AVAILABLE", (
        f"the executed plan settled at {detail['Status']!r} "
        f"({detail.get('StatusMessage')!r}), expected 'AVAILABLE'"
    )

    outputs = {o["OutputKey"]: o["OutputValue"] for o in
               sc.get_provisioned_product_outputs(ProvisionedProductId=pp_id)["Outputs"]}
    assert outputs.get("EnvEcho") == "prod", (
        f"the deployed template's EnvEcho output is {outputs.get('EnvEcho')!r}, expected 'prod'"
    )
    assert "CloudformationStackARN" in outputs, (
        f"GetProvisionedProductOutputs returned {sorted(outputs)!r} with no 'CloudformationStackARN'"
    )
    stack_arn = outputs["CloudformationStackARN"]

    final_record = sc.describe_record(Id=record_id)["RecordDetail"]
    assert final_record["Status"] == "SUCCEEDED", (
        f"DescribeRecord reports {final_record['Status']!r} for the executed plan's record, "
        f"expected 'SUCCEEDED'"
    )

    # ---- the delegation: CFN deployed under the LAUNCH role, not the unprivileged caller ----
    stack = cfn.describe_stacks(StackName=stack_arn)["Stacks"][0]
    assert stack["StackStatus"] == "CREATE_COMPLETE", (
        f"the deployed stack is {stack['StackStatus']!r}, expected 'CREATE_COMPLETE'"
    )
    stack_tags = {t["Key"]: t["Value"] for t in stack.get("Tags", [])}
    assert stack_tags.get("aws:servicecatalog:provisioningPrincipalArn") == caller_session_arn, (
        f"the stack's provisioningPrincipalArn tag is "
        f"{stack_tags.get('aws:servicecatalog:provisioningPrincipalArn')!r}, expected the "
        f"unprivileged caller {caller_session_arn!r}"
    )

    # That same caller cannot touch CloudFormation directly — its own policy denies it —
    # so the stack above was deployed by Service Catalog assuming the LAUNCH role, not the caller.
    cfn_as_caller = ctx.client("cloudformation", creds={
        "aws_access_key_id": caller_creds["AccessKeyId"],
        "aws_secret_access_key": caller_creds["SecretAccessKey"],
        "aws_session_token": caller_creds["SessionToken"]})
    denied_code = None
    try:
        cfn_as_caller.describe_stacks(StackName=stack_arn)
    except ClientError as exc:
        denied_code = exc.response.get("Error", {}).get("Code")
    assert denied_code == "AccessDenied", (
        f"the caller's own DescribeStacks answered {denied_code!r}, expected 'AccessDenied' — "
        f"if the caller could reach CloudFormation itself, the stack above would not show "
        f"the launch role actually did the work"
    )



if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
