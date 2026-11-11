"""terminate-provisioned-product-deletes-cloudformation-stack."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "terminate-provisioned-product-deletes-cloudformation-stack"
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


def _error_code(fn) -> tuple:
    """The botocore Error.Code and Error.Message raised by fn(). An unexpected SUCCESS raises
    rather than returning a falsy sentinel: an emulator still serving a terminated product is the
    strongest signal this check can produce and must not be reported as an error-code mismatch."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("the call was expected to fail after termination but succeeded")


def _launch_path(ctx, sc, s3, who, deadline: float = 120.0) -> tuple:
    """Build a launchable product from scratch: bucket, product, portfolio, both associations.
    Returns (product_id, artifact_id, path_id)."""
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
            return product_id, artifact_id, paths[0]["Id"]
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


def _await_record(sc, record_id: str, deadline: float) -> dict:
    end = time.time() + deadline
    while True:
        detail = sc.describe_record(Id=record_id)["RecordDetail"]
        if detail["Status"] not in ("CREATED", "IN_PROGRESS", "IN_PROGRESS_IN_ERROR"):
            return detail
        assert time.time() < end, (
            f"record {record_id!r} was still {detail['Status']!r} after {deadline}s"
        )
        time.sleep(5)


def _await_stack_status(cfn, stack_arn: str, want: str, deadline: float) -> str:
    end = time.time() + deadline
    while True:
        status = cfn.describe_stacks(StackName=stack_arn)["Stacks"][0]["StackStatus"]
        if status == want:
            return status
        assert time.time() < end, (
            f"stack {stack_arn!r} was {status!r} after {deadline}s, expected {want!r}"
        )
        time.sleep(5)


def _terminate_quietly(sc, pp_id: str) -> None:
    """Belt-and-braces teardown for the case where the body failed before terminating. DeleteProduct
    is registered earlier in the LIFO chain and fails while a provisioned product still references
    the product, so this waits rather than returning early."""
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


@tags("axis:happy-path", "concern:deploy", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """TerminateProvisionedProduct's record reaches SUCCEEDED, after which DescribeProvisionedProduct
    answers ResourceNotFoundException with its exact message and the deployed CloudFormation stack
    has no live resources left."""
    sc, who, _ = _launch_principal(ctx)
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")

    product_id, artifact_id, path_id = _launch_path(ctx, sc, s3, who)

    record = sc.provision_product(
        ProductId=product_id, ProvisioningArtifactId=artifact_id, PathId=path_id,
        ProvisionedProductName=ctx.unique_name("sim2real-sc-pp-"),
        ProvisionToken=uuid.uuid4().hex,
        ProvisioningParameters=[{"Key": "Env", "Value": "dev"}],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["RecordDetail"]
    pp_id = record["ProvisionedProductId"]
    ctx.on_cleanup(lambda: _terminate_quietly(sc, pp_id))

    detail = _await_settled(sc, pp_id, deadline=240.0)
    assert detail["Status"] == "AVAILABLE", (
        f"provisioning settled at {detail['Status']!r} ({detail.get('StatusMessage')!r}), "
        f"expected 'AVAILABLE' before a termination can be graded"
    )
    stack_arn = {o["OutputKey"]: o["OutputValue"] for o in
                 sc.get_provisioned_product_outputs(
                     ProvisionedProductId=pp_id)["Outputs"]}["CloudformationStackARN"]
    _await_stack_status(cfn, stack_arn, "CREATE_COMPLETE", 120.0)

    # ---- the transition under test ----
    term = sc.terminate_provisioned_product(
        ProvisionedProductId=pp_id, TerminateToken=uuid.uuid4().hex)["RecordDetail"]
    assert term["RecordType"] == "TERMINATE_PROVISIONED_PRODUCT", (
        f"the termination record type is {term['RecordType']!r}, "
        f"expected 'TERMINATE_PROVISIONED_PRODUCT'"
    )
    settled = _await_record(sc, term["RecordId"], deadline=240.0)
    assert settled["Status"] == "SUCCEEDED", (
        f"the termination record settled at {settled['Status']!r} "
        f"({settled.get('RecordErrors')!r}), expected 'SUCCEEDED'"
    )

    # The provisioned product is GONE, not merely marked terminated.
    code, message = _error_code(lambda: sc.describe_provisioned_product(Id=pp_id))
    assert code == "ResourceNotFoundException", (
        f"DescribeProvisionedProduct on the terminated product answered {code!r}, "
        f"expected 'ResourceNotFoundException'"
    )
    expected = f"Provisioned product not found: {pp_id}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # ...and the stack it deployed is deleted, which is the effect an emulator most easily fakes
    # by forgetting the provisioned product while leaving the infrastructure behind.
    _await_stack_status(cfn, stack_arn, "DELETE_COMPLETE", 240.0)
    live = [r for r in cfn.describe_stack_resources(StackName=stack_arn)["StackResources"]
            if r["ResourceStatus"] != "DELETE_COMPLETE"]
    assert live == [], (
        f"the deleted stack still reports live resources: "
        f"{[(r['LogicalResourceId'], r['ResourceStatus']) for r in live]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
