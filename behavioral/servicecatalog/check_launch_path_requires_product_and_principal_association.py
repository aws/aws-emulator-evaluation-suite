"""launch-path-requires-product-and-principal-association."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "launch-path-requires-product-and-principal-association"
GROUP = 'launch-paths'
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


def _ignore_not_found(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _await_paths(sc, product_id: str, want: bool, deadline: float) -> list:
    """Poll for the launch-path population reaching the wanted emptiness. Returns the last
    reading so the caller can assert on it; never sleeps as a substitute for the poll."""
    end = time.time() + deadline
    while True:
        paths = _launch_paths(sc, product_id)
        if bool(paths) == want:
            return paths
        if time.time() >= end:
            return paths
        time.sleep(3)


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
    """A product has no launch path until it is associated with a portfolio AND the caller's role is a
    portfolio principal; then exactly one path, named for that portfolio, resolves, and removing the
    principal association removes it again."""
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
    ctx.on_cleanup(lambda: sc.delete_product(Id=product_id))

    # 1. No portfolio, no principal: the product exists but is not launchable.
    assert _launch_paths(sc, product_id) == [], (
        f"a product in no portfolio already had launch paths: "
        f"{_launch_paths(sc, product_id)!r}"
    )

    portfolio = sc.create_portfolio(
        DisplayName=ctx.unique_name("sim2real-sc-pf-"), ProviderName="sim2real",
        Description="sim2real service-catalog behavioral check",
        IdempotencyToken=uuid.uuid4().hex, Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["PortfolioDetail"]
    portfolio_id = portfolio["Id"]
    ctx.on_cleanup(lambda: sc.delete_portfolio(Id=portfolio_id))

    # 2. Product associated, principal NOT: the association is visible on the product, and the
    #    product is STILL not launchable. This is the half an over-permissive emulator skips.
    sc.associate_product_with_portfolio(ProductId=product_id, PortfolioId=portfolio_id)
    ctx.on_cleanup(lambda: sc.disassociate_product_from_portfolio(
        ProductId=product_id, PortfolioId=portfolio_id))

    linked, token = [], None
    while True:
        kw = {"ProductId": product_id}
        if token:
            kw["PageToken"] = token
        page = sc.list_portfolios_for_product(**kw)
        linked.extend(d["Id"] for d in page.get("PortfolioDetails", []))
        token = page.get("NextPageToken")
        if not token:
            break
    assert portfolio_id in linked, (
        f"after AssociateProductWithPortfolio, ListPortfoliosForProduct returned {linked!r}, "
        f"which does not contain {portfolio_id!r}"
    )

    still = _await_paths(sc, product_id, want=False, deadline=45.0)
    assert still == [], (
        f"the product became launchable on the portfolio association alone: {still!r} — real AWS "
        f"also requires AssociatePrincipalWithPortfolio for the calling principal"
    )

    # 3. Principal associated too: a path resolves, and it names the portfolio that granted it.
    sc.associate_principal_with_portfolio(
        PortfolioId=portfolio_id, PrincipalARN=who, PrincipalType="IAM")
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: sc.disassociate_principal_from_portfolio(
        PortfolioId=portfolio_id, PrincipalARN=who)))

    paths = _await_paths(sc, product_id, want=True, deadline=120.0)
    assert len(paths) == 1, (
        f"expected exactly one launch path once both associations exist, got {paths!r}"
    )
    assert paths[0]["Name"] == portfolio["DisplayName"], (
        f"launch path is named {paths[0]['Name']!r}, expected the granting portfolio's display "
        f"name {portfolio['DisplayName']!r}"
    )
    assert paths[0].get("Id"), f"launch path carries no Id: {paths[0]!r}"

    # 4. Revoking the principal revokes launchability — the gate is live state, not a one-way latch.
    sc.disassociate_principal_from_portfolio(PortfolioId=portfolio_id, PrincipalARN=who)
    revoked = _await_paths(sc, product_id, want=False, deadline=45.0)
    assert revoked == [], (
        f"after DisassociatePrincipalFromPortfolio the product was still launchable: {revoked!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
