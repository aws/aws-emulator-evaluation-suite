"""copy-product-result-rejected-until-portfolio-access."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "copy-product-result-rejected-until-portfolio-access"
GROUP = 'provisioning'
SERVICES = ["servicecatalog"]


_TEMPLATE = {
    "AWSTemplateFormatVersion": "2010-09-09",
    "Resources": {"Marker": {"Type": "AWS::CloudFormation::WaitConditionHandle"}},
}

_SESSION_NAME = "sim2real-sc-session"


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        for obj in page.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket)


def _host_template(ctx, s3) -> str:
    bucket = ctx.unique_name("sim2real-sc-tpl-")
    kw = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kw["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kw)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_object(Bucket=bucket, Key="product.json", Body=json.dumps(_TEMPLATE).encode())
    return ctx.s3_object_url(f"https://s3.{ctx.region}.amazonaws.com/{bucket}/product.json", bucket, "product.json")


def _reader_principal(ctx, iam, sts, account: str) -> tuple:
    """A fresh role, trusted by this account, that can only read the Service Catalog catalog.

    Returns (client, role_arn, session_arn).
    """
    role_name = ctx.unique_name("sim2real-sc-reader-")[:64]
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
        "Action": "sts:AssumeRole"}]}
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": ["servicecatalog:DescribeProduct",
                                        "servicecatalog:DescribeProductView"], "Resource": "*"}]}
    iam.put_role_policy(RoleName=role_name, PolicyName="sim2real-sc-policy",
                         PolicyDocument=json.dumps(policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-sc-policy"))
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
    client = ctx.client("servicecatalog", creds={
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretAccessKey"],
        "aws_session_token": creds["SessionToken"]})
    return client, role_arn, session_arn


def _error_code(fn) -> tuple:
    """The Error.Code and Error.Message ``fn`` raises. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _await_copy(sc, token: str, deadline: float) -> dict:
    end = time.time() + deadline
    while True:
        detail = sc.describe_copy_product_status(CopyProductToken=token)
        if detail["CopyProductStatus"] != "IN_PROGRESS":
            return detail
        assert time.time() < end, f"copy {token!r} was still IN_PROGRESS after {deadline}s"
        time.sleep(3)


@tags("axis:rejection", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data", "cap:c1")
def run(ctx) -> None:
    """CopyProduct's result is a product in its own right: a reader cannot see it through the
    source's portfolio grant, but once it is associated with a portfolio, DescribeProduct and
    DescribeProductView return its own provisioning artifact, not the source's.
    """
    sc_admin = ctx.client("servicecatalog")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    s3 = ctx.client("s3")
    account = sts.get_caller_identity()["Account"]

    reader, reader_arn, _ = _reader_principal(ctx, iam, sts, account)

    url = _host_template(ctx, s3)
    source = sc_admin.create_product(
        Name=ctx.unique_name("sim2real-sc-src-"), Owner="sim2real",
        ProductType="CLOUD_FORMATION_TEMPLATE", IdempotencyToken=uuid.uuid4().hex,
        ProvisioningArtifactParameters={"Name": "v1", "Type": "CLOUD_FORMATION_TEMPLATE",
                                        "Info": {"LoadTemplateFromURL": url}},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    source_id = source["ProductViewDetail"]["ProductViewSummary"]["ProductId"]
    source_arn = source["ProductViewDetail"]["ProductARN"]
    ctx.on_cleanup(lambda: sc_admin.delete_product(Id=source_id))

    portfolio_id = sc_admin.create_portfolio(
        DisplayName=ctx.unique_name("sim2real-sc-pf-"), ProviderName="sim2real",
        IdempotencyToken=uuid.uuid4().hex, Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["PortfolioDetail"]["Id"]
    ctx.on_cleanup(lambda: sc_admin.delete_portfolio(Id=portfolio_id))

    sc_admin.associate_product_with_portfolio(ProductId=source_id, PortfolioId=portfolio_id)
    ctx.on_cleanup(lambda: sc_admin.disassociate_product_from_portfolio(
        ProductId=source_id, PortfolioId=portfolio_id))
    sc_admin.associate_principal_with_portfolio(
        PortfolioId=portfolio_id, PrincipalARN=reader_arn, PrincipalType="IAM")
    ctx.on_cleanup(lambda: sc_admin.disassociate_principal_from_portfolio(
        PortfolioId=portfolio_id, PrincipalARN=reader_arn))

    # ---- positive control: the reader can already see the SOURCE through the portfolio grant ----
    end = time.time() + 60.0
    while True:
        try:
            reader.describe_product(Id=source_id)
            break
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException" or time.time() > end:
                raise
            time.sleep(3)

    copy_token = sc_admin.copy_product(
        SourceProductArn=source_arn, IdempotencyToken=uuid.uuid4().hex)["CopyProductToken"]
    copy_detail = _await_copy(sc_admin, copy_token, deadline=120.0)
    assert copy_detail["CopyProductStatus"] == "SUCCEEDED", (
        f"CopyProduct settled at {copy_detail['CopyProductStatus']!r} "
        f"({copy_detail.get('StatusDetail')!r}), expected 'SUCCEEDED'"
    )
    target_id = copy_detail["TargetProductId"]
    ctx.on_cleanup(lambda: sc_admin.delete_product(Id=target_id))

    # ---- the negative: the SAME reader, with the SAME IAM permission, cannot see the COPY yet ----
    code, message = _error_code(lambda: reader.describe_product(Id=target_id))
    assert code == "ResourceNotFoundException", (
        f"the reader's DescribeProduct on the un-granted copy answered {code!r}, "
        f"expected 'ResourceNotFoundException' — IAM permission alone is not portfolio access"
    )
    expected_message = f"{target_id} does not exist or access was denied"
    assert message == expected_message, (
        f"the reader's DescribeProduct on the un-granted copy said {message!r}, "
        f"expected {expected_message!r}"
    )

    # ---- grant the copy the same access, and the SAME reader now sees ITS OWN artifact ----
    sc_admin.associate_product_with_portfolio(ProductId=target_id, PortfolioId=portfolio_id)
    ctx.on_cleanup(lambda: sc_admin.disassociate_product_from_portfolio(
        ProductId=target_id, PortfolioId=portfolio_id))

    end = time.time() + 60.0
    while True:
        try:
            target_detail = reader.describe_product(Id=target_id)
            break
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException" or time.time() > end:
                raise
            time.sleep(3)
    source_artifacts = reader.describe_product(Id=source_id)["ProvisioningArtifacts"]
    target_artifacts = target_detail["ProvisioningArtifacts"]
    assert len(target_artifacts) == len(source_artifacts) == 1, (
        f"source has {len(source_artifacts)} artifact(s), copy has {len(target_artifacts)}, "
        f"expected exactly 1 each"
    )
    assert target_artifacts[0]["Id"] != source_artifacts[0]["Id"], (
        f"the copy's provisioning artifact id {target_artifacts[0]['Id']!r} is the SOURCE's own "
        f"artifact id — the copy must mint its own, not alias the source's"
    )

    target_view_id = target_detail["ProductViewSummary"]["Id"]
    end = time.time() + 60.0
    while True:
        try:
            view = reader.describe_product_view(Id=target_view_id)
            break
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException" or time.time() > end:
                raise
            time.sleep(3)
    assert view["ProductViewSummary"]["ProductId"] == target_id, (
        f"DescribeProductView on the copy's view id resolved to product "
        f"{view['ProductViewSummary']['ProductId']!r}, expected the copy {target_id!r}"
    )
    assert len(view["ProvisioningArtifacts"]) == 1, (
        f"DescribeProductView on the copy reported {len(view['ProvisioningArtifacts'])} "
        f"provisioning artifact(s), expected exactly 1"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
