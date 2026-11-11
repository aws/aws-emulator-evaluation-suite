"""provisioned-product-creates-cloudformation-stack."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "provisioned-product-creates-cloudformation-stack"
GROUP = 'deploy-provisioning'
SERVICES = ["servicecatalog"]

_TEMPLATE = {
    "AWSTemplateFormatVersion": "2010-09-09",
    "Parameters": {"Env": {"Type": "String", "AllowedValues": ["dev", "prod"], "Default": "dev"}},
    "Resources": {"Marker": {"Type": "AWS::CloudFormation::WaitConditionHandle"}},
    "Outputs": {"EnvEcho": {"Value": {"Ref": "Env"}},
                "StackRegion": {"Value": {"Ref": "AWS::Region"}}},
}


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        for obj in page.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket)


def _host_template(ctx, s3) -> str:
    """Publish the product template to a bucket this check owns; return the URL Service Catalog
    reads it from. Nothing pre-existing is used — a fresh account has no bucket to borrow."""
    bucket = ctx.unique_name("sim2real-sc-tpl-")
    kw = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kw["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kw)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_object(Bucket=bucket, Key="product.json", Body=json.dumps(_TEMPLATE).encode())
    return ctx.s3_object_url(f"https://s3.{ctx.region}.amazonaws.com/{bucket}/product.json", bucket, "product.json")


def _launch_path(ctx, sc, s3, who, deadline: float = 120.0) -> tuple:
    """Build a launchable product from scratch: bucket, product, portfolio, both associations.
    Returns (product_id, artifact_id, portfolio_id, path_id)."""
    url = _host_template(ctx, s3)
    product = sc.create_product(
        Name=ctx.unique_name("sim2real-sc-prod-"), Owner="sim2real",
        Description="sim2real service-catalog behavioral check",
        ProductType="CLOUD_FORMATION_TEMPLATE", IdempotencyToken=uuid.uuid4().hex,
        ProvisioningArtifactParameters={"Name": "v1", "Type": "CLOUD_FORMATION_TEMPLATE",
                                        "Info": {"LoadTemplateFromURL": url}},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    product_id = product["ProductViewDetail"]["ProductViewSummary"]["ProductId"]
    artifact_id = product["ProvisioningArtifactDetail"]["Id"]
    ctx.on_cleanup(lambda: sc.delete_product(Id=product_id))

    portfolio_id = sc.create_portfolio(
        DisplayName=ctx.unique_name("sim2real-sc-pf-"), ProviderName="sim2real",
        Description="sim2real service-catalog behavioral check",
        IdempotencyToken=uuid.uuid4().hex, Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["PortfolioDetail"]["Id"]
    ctx.on_cleanup(lambda: sc.delete_portfolio(Id=portfolio_id))

    sc.associate_product_with_portfolio(ProductId=product_id, PortfolioId=portfolio_id)
    ctx.on_cleanup(lambda: sc.disassociate_product_from_portfolio(
        ProductId=product_id, PortfolioId=portfolio_id))
    sc.associate_principal_with_portfolio(
        PortfolioId=portfolio_id, PrincipalARN=who, PrincipalType="IAM")
    ctx.on_cleanup(lambda: sc.disassociate_principal_from_portfolio(
        PortfolioId=portfolio_id, PrincipalARN=who))

    end = time.time() + deadline
    while True:
        try:
            paths = sc.list_launch_paths(ProductId=product_id).get("LaunchPathSummaries", [])
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise
            paths = []
        if paths:
            return product_id, artifact_id, portfolio_id, paths[0]["Id"]
        assert time.time() < end, (
            f"no launch path resolved for {product_id!r} within {deadline}s"
        )
        time.sleep(3)


def _await_settled(sc, pp_id: str, deadline: float) -> dict:
    end = time.time() + deadline
    while True:
        detail = sc.describe_provisioned_product(Id=pp_id)["ProvisionedProductDetail"]
        if detail["Status"] not in ("UNDER_CHANGE", "PLAN_IN_PROGRESS"):
            return detail
        assert time.time() < end, (
            f"provisioned product {pp_id!r} was still {detail['Status']!r} after {deadline}s"
        )
        time.sleep(5)


def _terminate(sc, pp_id: str) -> None:
    """Terminate and WAIT. DeleteProduct is registered earlier in the LIFO chain and fails while
    a provisioned product still references the product, so returning early strands both."""
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


def _launch_principal(ctx) -> tuple:
    """A Service Catalog client signed as an IAM role this check creates, and the role's ARN.
    The role is the portfolio principal, so launch access is granted to an identity the check
    owns rather than to whoever runs it. Returns (client, role_arn, session_arn)."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-sc-user-")[:64]
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
        "Action": "sts:AssumeRole"}]}
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": ["servicecatalog:*", "cloudformation:*"], "Resource": "*"},
        {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
        {"Effect": "Allow", "Action": "iam:GetRole", "Resource": role_arn}]}
    iam.put_role_policy(RoleName=role_name, PolicyName="sim2real-sc-user",
                        PolicyDocument=json.dumps(policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-sc-user"))
    session_name = "sim2real-sc-user"
    end = time.time() + 60.0
    while True:
        try:
            creds = sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)["Credentials"]
            break
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "AccessDenied" or time.time() > end:
                raise
            time.sleep(3)
    sc = ctx.client("servicecatalog", creds={
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretAccessKey"],
        "aws_session_token": creds["SessionToken"]})
    # The inline policy reaches the new session after IAM propagation; wait for a read to pass.
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
    return sc, role_arn, f"arn:aws:sts::{account}:assumed-role/{role_name}/{session_name}"


@tags("axis:happy-path", "concern:deploy", "concern:data-plane", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """A provisioned product reaches AVAILABLE and deploys a CREATE_COMPLETE CloudFormation stack named
    SC-<account>-<id> whose parameters, resources and outputs match the launch, and whose tags name the
    portfolio, product, artifact, principal and provisioned product."""
    sc, who, session_arn = _launch_principal(ctx)
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    account = who.split(":")[4]

    product_id, artifact_id, portfolio_id, path_id = _launch_path(ctx, sc, s3, who)

    pp_name = ctx.unique_name("sim2real-sc-pp-")
    record = sc.provision_product(
        ProductId=product_id, ProvisioningArtifactId=artifact_id, PathId=path_id,
        ProvisionedProductName=pp_name, ProvisionToken=uuid.uuid4().hex,
        ProvisioningParameters=[{"Key": "Env", "Value": "prod"}],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["RecordDetail"]
    pp_id = record["ProvisionedProductId"]
    ctx.on_cleanup(lambda: _terminate(sc, pp_id))

    assert record["ProvisionedProductType"] == "CFN_STACK", (
        f"Service Catalog reported the provisioned product type as "
        f"{record['ProvisionedProductType']!r}, expected 'CFN_STACK'"
    )
    detail = _await_settled(sc, pp_id, deadline=240.0)
    assert detail["Status"] == "AVAILABLE", (
        f"provisioning settled at {detail['Status']!r} ({detail.get('StatusMessage')!r}), "
        f"expected 'AVAILABLE'"
    )

    # Service Catalog injects a stack ARN output the template never declared — that ARN, not a
    # name we reconstruct ourselves, is the handle onto the deployed stack.
    outputs = {o["OutputKey"]: o["OutputValue"] for o in
               sc.get_provisioned_product_outputs(ProvisionedProductId=pp_id)["Outputs"]}
    assert "CloudformationStackARN" in outputs, (
        f"GetProvisionedProductOutputs returned {sorted(outputs)!r} with no "
        f"'CloudformationStackARN' — Service Catalog did not report a deployed stack"
    )
    assert outputs.get("EnvEcho") == "prod", (
        f"the template output EnvEcho came back {outputs.get('EnvEcho')!r}, expected 'prod' — the "
        f"ProvisioningParameters value did not reach the deployed template"
    )
    assert outputs.get("StackRegion") == ctx.region, (
        f"the stack deployed into region {outputs.get('StackRegion')!r}, expected {ctx.region!r}"
    )
    stack_arn = outputs["CloudformationStackARN"]

    stack = cfn.describe_stacks(StackName=stack_arn)["Stacks"][0]
    assert stack["StackStatus"] == "CREATE_COMPLETE", (
        f"the deployed stack is {stack['StackStatus']!r}, expected 'CREATE_COMPLETE'"
    )
    assert stack["StackName"] == f"SC-{account}-{pp_id}", (
        f"Service Catalog named the stack {stack['StackName']!r}, expected "
        f"'SC-{account}-{pp_id}' — the stack must be traceable to its provisioned product"
    )
    stack_params = {p["ParameterKey"]: p["ParameterValue"] for p in stack.get("Parameters", [])}
    assert stack_params == {"Env": "prod"}, (
        f"the stack was created with parameters {stack_params!r}, expected {{'Env': 'prod'}}"
    )
    stack_outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    assert stack_outputs.get("EnvEcho") == "prod", (
        f"the stack's own EnvEcho output is {stack_outputs.get('EnvEcho')!r}, expected 'prod'"
    )

    resources = {r["LogicalResourceId"]: r for r in
                 cfn.describe_stack_resources(StackName=stack_arn)["StackResources"]}
    assert set(resources) == {"Marker"}, (
        f"the stack holds resources {sorted(resources)!r}, expected exactly ['Marker'] from the "
        f"product template"
    )
    assert resources["Marker"]["ResourceStatus"] == "CREATE_COMPLETE", (
        f"the template's resource is {resources['Marker']['ResourceStatus']!r}, "
        f"expected 'CREATE_COMPLETE' — a deployed product must actually function"
    )

    # The governance trail: Service Catalog stamps the stack with the graph it launched through.
    stack_tags = {t["Key"]: t["Value"] for t in stack.get("Tags", [])}
    assert stack_tags.get("aws:servicecatalog:portfolioArn", "").endswith(f"/{portfolio_id}"), (
        f"the stack's aws:servicecatalog:portfolioArn tag is "
        f"{stack_tags.get('aws:servicecatalog:portfolioArn')!r}, which does not name the "
        f"granting portfolio {portfolio_id!r}"
    )
    assert stack_tags.get("aws:servicecatalog:productArn", "").endswith(f"/{product_id}"), (
        f"the stack's aws:servicecatalog:productArn tag is "
        f"{stack_tags.get('aws:servicecatalog:productArn')!r}, which does not name {product_id!r}"
    )
    assert stack_tags.get("aws:servicecatalog:provisioningArtifactIdentifier") == artifact_id, (
        f"the stack's provisioningArtifactIdentifier tag is "
        f"{stack_tags.get('aws:servicecatalog:provisioningArtifactIdentifier')!r}, "
        f"expected {artifact_id!r}"
    )
    assert stack_tags.get("aws:servicecatalog:provisioningPrincipalArn") == session_arn, (
        f"the stack's provisioningPrincipalArn tag is "
        f"{stack_tags.get('aws:servicecatalog:provisioningPrincipalArn')!r}, expected {session_arn!r}"
    )
    assert stack_tags.get("aws:servicecatalog:provisionedProductArn", "").endswith(f"/{pp_id}"), (
        f"the stack's provisionedProductArn tag is "
        f"{stack_tags.get('aws:servicecatalog:provisionedProductArn')!r}, "
        f"which does not name {pp_id!r}"
    )
    assert stack_tags.get("sim2real") == CHECK, (
        f"the Tags passed to ProvisionProduct did not reach the stack: {sorted(stack_tags)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
