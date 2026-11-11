"""provision-unassociated-product-rejected."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "provision-unassociated-product-rejected"
GROUP = 'provisioning'
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


def _error_code(fn) -> tuple:
    """The botocore Error.Code and Error.Message raised by fn(). An unexpected SUCCESS raises
    rather than returning
    a falsy sentinel: an emulator accepting what real AWS refuses is the strongest signal this
    check can produce and must not be reported as an error-code mismatch."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("ProvisionProduct was expected to fail on real AWS but succeeded")


def _launch_paths(sc, product_id: str) -> list:
    """Every launch path for a product, following PageToken. ResourceNotFoundException means
    'not launchable' rather than 'no such product', so it maps to the empty list."""
    out, token = [], None
    while True:
        kw = {"ProductId": product_id}
        if token:
            kw["PageToken"] = token
        try:
            page = sc.list_launch_paths(**kw)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise
            return []
        out.extend(page.get("LaunchPathSummaries", []))
        token = page.get("NextPageToken")
        if not token:
            return out


def _await_paths(sc, product_id: str, deadline: float) -> list:
    end = time.time() + deadline
    while True:
        paths = _launch_paths(sc, product_id)
        if paths:
            return paths
        assert time.time() < end, (
            f"no launch path resolved for {product_id!r} within {deadline}s"
        )
        time.sleep(3)


def _named(sc, name: str) -> list:
    """Provisioned-product names matching the exact name this check minted, paginated. The
    server-side name filter is what makes 'empty' a property of the QUERY rather than of whatever
    else the account holds."""
    out, token = [], None
    while True:
        kw = {"Filters": {"SearchQuery": [f"name:{name}"]},
              "AccessLevelFilter": {"Key": "Account", "Value": "self"}}
        if token:
            kw["PageToken"] = token
        page = sc.search_provisioned_products(**kw)
        out.extend(p["Name"] for p in page.get("ProvisionedProducts", []))
        token = page.get("NextPageToken")
        if not token:
            return out


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


@tags("axis:rejection", "concern:negative-classes", "plane:control", "cap:c1")
def run(ctx) -> None:
    """ProvisionProduct on a product in no portfolio answers ResourceNotFoundException ("No launch
    paths found") and provisions nothing, and the same call succeeds once the product and the
    calling principal are associated with a portfolio."""
    sc, who, _ = _launch_principal(ctx)
    s3 = ctx.client("s3")

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

    # ---- the negative: exactly one thing is missing, the portfolio/principal grant ----
    refused_name = ctx.unique_name("sim2real-sc-pp-")
    code, message = _error_code(lambda: sc.provision_product(
        ProductId=product_id, ProvisioningArtifactId=artifact_id,
        ProvisionedProductName=refused_name, ProvisionToken=uuid.uuid4().hex,
        ProvisioningParameters=[{"Key": "Env", "Value": "prod"}],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    ))
    assert code == "ResourceNotFoundException", (
        f"ProvisionProduct on an unassociated product answered {code!r}, "
        f"expected 'ResourceNotFoundException'"
    )
    expected = f"No launch paths found for resource: {product_id}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # ...and the effect is ABSENT: the refusal minted no provisioned product.
    assert _named(sc, refused_name) == [], (
        f"the refused ProvisionProduct still created a provisioned product named "
        f"{refused_name!r}: {_named(sc, refused_name)!r}"
    )

    # ---- the positive control: the SAME request, once the grant exists ----
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

    path_id = _await_paths(sc, product_id, deadline=120.0)[0]["Id"]
    allowed_name = ctx.unique_name("sim2real-sc-pp-")
    record = sc.provision_product(
        ProductId=product_id, ProvisioningArtifactId=artifact_id, PathId=path_id,
        ProvisionedProductName=allowed_name, ProvisionToken=uuid.uuid4().hex,
        ProvisioningParameters=[{"Key": "Env", "Value": "prod"}],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["RecordDetail"]
    pp_id = record["ProvisionedProductId"]
    ctx.on_cleanup(lambda: _terminate(sc, pp_id))

    assert record["PathId"] == path_id, (
        f"the accepted record was provisioned through path {record['PathId']!r}, "
        f"not the granted path {path_id!r}"
    )
    detail = _await_settled(sc, pp_id, deadline=180.0)
    assert detail["Status"] == "AVAILABLE", (
        f"the granted ProvisionProduct settled at {detail['Status']!r} "
        f"({detail.get('StatusMessage')!r}), expected 'AVAILABLE'"
    )
    assert _named(sc, allowed_name) == [allowed_name], (
        f"the granted provisioned product is not findable by its own name: "
        f"{_named(sc, allowed_name)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
