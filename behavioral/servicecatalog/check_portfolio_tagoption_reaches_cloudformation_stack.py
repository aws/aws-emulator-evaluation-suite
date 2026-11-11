"""portfolio-tagoption-reaches-cloudformation-stack."""
# ListTagOptions answers TagOptionNotMigratedException on an account whose TagOption library was
# never written; CreateTagOption migrates the library, so this check creates before it reads.
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "portfolio-tagoption-reaches-cloudformation-stack"
GROUP = 'deploy-tagoptions'
SERVICES = ["servicecatalog"]

# ===== helpers =====

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


def _ignore_not_found(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


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


def _resources_for_tagoption(sc, tagoption_id: str) -> list:
    """Resource ids carrying a TagOption, following PageToken."""
    out, token = [], None
    while True:
        kw = {"TagOptionId": tagoption_id}
        if token:
            kw["PageToken"] = token
        page = sc.list_resources_for_tag_option(**kw)
        out.extend(r["Id"] for r in page.get("ResourceDetails", []))
        token = page.get("PageToken")
        if not token:
            return out


@tags("axis:happy-path", "concern:deploy", "concern:data-plane", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """A TagOption associated with a portfolio surfaces in DescribeProvisioningParameters' TagOptions
    for the launch path and is applied as a tag on the CloudFormation stack the launch deploys,
    with its single allowed value selected automatically."""
    sc = ctx.client("servicecatalog")
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    who = ctx.client("sts").get_caller_identity()["Arn"]

    # Key and value are per-run so two concurrent runs in this account cannot collide, and so the
    # assertions below are about THIS TagOption rather than about the account's library.
    tag_key = ctx.unique_name("sim2realtagopt")
    tag_value = ctx.unique_name("tv")
    tagoption_id = sc.create_tag_option(Key=tag_key, Value=tag_value)["TagOptionDetail"]["Id"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: sc.delete_tag_option(Id=tagoption_id)))

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

    # The TagOption goes on the PORTFOLIO — never on the product, never on the launch request.
    sc.associate_tag_option_with_resource(ResourceId=portfolio_id, TagOptionId=tagoption_id)
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: sc.disassociate_tag_option_from_resource(
        ResourceId=portfolio_id, TagOptionId=tagoption_id)))
    assert _resources_for_tagoption(sc, tagoption_id) == [portfolio_id], (
        f"ListResourcesForTagOption reports the TagOption on "
        f"{_resources_for_tagoption(sc, tagoption_id)!r}, expected exactly [{portfolio_id!r}]"
    )

    end = time.time() + 120.0
    while True:
        try:
            paths = sc.list_launch_paths(ProductId=product_id).get("LaunchPathSummaries", [])
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise
            paths = []
        if paths:
            break
        assert time.time() < end, f"no launch path resolved for {product_id!r} within 120s"
        time.sleep(3)
    path_id = paths[0]["Id"]

    # Hop one: the portfolio's TagOption is offered on the product's launch path.
    params = sc.describe_provisioning_parameters(
        ProductId=product_id, ProvisioningArtifactId=artifact_id, PathId=path_id)
    offered = {t["Key"]: t.get("Values", []) for t in params.get("TagOptions", [])}
    assert offered == {tag_key: [tag_value]}, (
        f"DescribeProvisioningParameters offered TagOptions {offered!r}, expected "
        f"{{{tag_key!r}: [{tag_value!r}]}} inherited from the portfolio"
    )

    # Hop two: the launch applies it to the deployed stack, without being asked to.
    record = sc.provision_product(
        ProductId=product_id, ProvisioningArtifactId=artifact_id, PathId=path_id,
        ProvisionedProductName=ctx.unique_name("sim2real-sc-pp-"),
        ProvisionToken=uuid.uuid4().hex,
        ProvisioningParameters=[{"Key": "Env", "Value": "dev"}],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["RecordDetail"]
    pp_id = record["ProvisionedProductId"]
    ctx.on_cleanup(lambda: _terminate(sc, pp_id))

    detail = _await_settled(sc, pp_id, deadline=240.0)
    assert detail["Status"] == "AVAILABLE", (
        f"provisioning settled at {detail['Status']!r} ({detail.get('StatusMessage')!r}), "
        f"expected 'AVAILABLE'"
    )
    stack_arn = {o["OutputKey"]: o["OutputValue"] for o in
                 sc.get_provisioned_product_outputs(
                     ProvisionedProductId=pp_id)["Outputs"]}["CloudformationStackARN"]
    stack_tags = {t["Key"]: t["Value"] for t in
                  cfn.describe_stacks(StackName=stack_arn)["Stacks"][0].get("Tags", [])}
    assert stack_tags.get(tag_key) == tag_value, (
        f"the portfolio's TagOption {tag_key!r} did not reach the deployed stack: its tags are "
        f"{sorted(stack_tags)!r} and {tag_key!r} reads {stack_tags.get(tag_key)!r}, "
        f"expected {tag_value!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
