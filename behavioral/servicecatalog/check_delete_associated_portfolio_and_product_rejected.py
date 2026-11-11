"""delete-associated-portfolio-and-product-rejected."""
from __future__ import annotations

import json
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-associated-portfolio-and-product-rejected"
GROUP = 'portfolios'
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
    """The botocore Error.Code and Error.Message raised by fn(). An unexpected SUCCESS raises rather than returning a
    falsy sentinel: an emulator that deletes what real AWS protects is the strongest signal this
    check can produce and must not be reported as an error-code mismatch."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("the call was expected to fail on real AWS but succeeded")


def _ignore_not_found(fn) -> None:
    """Teardown for a resource the body itself is expected to delete."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _portfolios_for_product(sc, product_id: str) -> list:
    """Portfolio ids a product is associated with, following PageToken."""
    out, token = [], None
    while True:
        kw = {"ProductId": product_id}
        if token:
            kw["PageToken"] = token
        page = sc.list_portfolios_for_product(**kw)
        out.extend(p["Id"] for p in page.get("PortfolioDetails", []))
        token = page.get("NextPageToken")
        if not token:
            return out


@tags("axis:rejection", "concern:negative-classes", "plane:control", "cap:c1")
def run(ctx) -> None:
    """While a product is associated with a portfolio, DeletePortfolio and DeleteProduct are both refused
    with ResourceInUseException and the exact message, and both resources and the association stay
    intact; once disassociated, both deletes succeed and reads answer ResourceNotFoundException."""
    sc = ctx.client("servicecatalog")
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
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: sc.delete_product(Id=product_id)))

    portfolio = sc.create_portfolio(
        DisplayName=ctx.unique_name("sim2real-sc-pf-"), ProviderName="sim2real",
        Description="sim2real service-catalog behavioral check",
        IdempotencyToken=uuid.uuid4().hex, Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["PortfolioDetail"]
    portfolio_id = portfolio["Id"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: sc.delete_portfolio(Id=portfolio_id)))

    sc.associate_product_with_portfolio(ProductId=product_id, PortfolioId=portfolio_id)
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: sc.disassociate_product_from_portfolio(
        ProductId=product_id, PortfolioId=portfolio_id)))
    assert _portfolios_for_product(sc, product_id) == [portfolio_id], (
        f"the product reports portfolios {_portfolios_for_product(sc, product_id)!r}, expected "
        f"exactly [{portfolio_id!r}] — the association under test was not established"
    )

    # ---- the negative: the association is load-bearing in BOTH directions ----
    pf_code, pf_message = _error_code(lambda: sc.delete_portfolio(Id=portfolio_id))
    assert pf_code == "ResourceInUseException", (
        f"DeletePortfolio on a portfolio with an associated product answered {pf_code!r}, "
        f"expected 'ResourceInUseException'"
    )
    expected = f"Portfolio {portfolio_id} still has associated Products"
    assert pf_message == expected, f"expected message {expected!r}, got {pf_message!r}"
    prod_code, prod_message = _error_code(lambda: sc.delete_product(Id=product_id))
    assert prod_code == "ResourceInUseException", (
        f"DeleteProduct on a product associated with a portfolio answered {prod_code!r}, "
        f"expected 'ResourceInUseException'"
    )
    expected = f"Product {product_id} still assigned to Portfolio(s), has Users, or has Constraints."
    assert prod_message == expected, f"expected message {expected!r}, got {prod_message!r}"

    # ...and the effect is ABSENT: neither refused delete damaged its target or the edge between
    # them. A half-applied delete would show up here and nowhere in the error envelope.
    survivor = sc.describe_portfolio(Id=portfolio_id)["PortfolioDetail"]
    assert survivor["DisplayName"] == portfolio["DisplayName"], (
        f"the portfolio's DisplayName reads {survivor['DisplayName']!r} after a refused "
        f"DeletePortfolio, expected {portfolio['DisplayName']!r}"
    )
    surviving = sc.describe_product_as_admin(Id=product_id)
    assert surviving["ProductViewDetail"]["ProductViewSummary"]["ProductId"] == product_id, (
        f"the product is no longer readable by its own id after a refused DeleteProduct: "
        f"{surviving['ProductViewDetail']['ProductViewSummary']!r}"
    )
    assert len(surviving["ProvisioningArtifactSummaries"]) == 1, (
        f"the refused DeleteProduct left the product with "
        f"{len(surviving['ProvisioningArtifactSummaries'])} provisioning artifacts, expected 1"
    )
    assert _portfolios_for_product(sc, product_id) == [portfolio_id], (
        f"the association itself did not survive the two refused deletes: "
        f"{_portfolios_for_product(sc, product_id)!r}, expected [{portfolio_id!r}]"
    )

    # ---- the positive control: remove only the edge, and the SAME two deletes succeed ----
    sc.disassociate_product_from_portfolio(ProductId=product_id, PortfolioId=portfolio_id)
    assert _portfolios_for_product(sc, product_id) == [], (
        f"the product is still in portfolios after disassociation: "
        f"{_portfolios_for_product(sc, product_id)!r}"
    )

    sc.delete_portfolio(Id=portfolio_id)
    sc.delete_product(Id=product_id)
    gone_pf, gone_pf_message = _error_code(lambda: sc.describe_portfolio(Id=portfolio_id))
    assert gone_pf == "ResourceNotFoundException", (
        f"DescribePortfolio after a successful DeletePortfolio answered {gone_pf!r}, "
        f"expected 'ResourceNotFoundException'"
    )
    expected = f"There are no local or default portfolios with id {portfolio_id}"
    assert gone_pf_message == expected, f"expected message {expected!r}, got {gone_pf_message!r}"
    gone_prod, gone_prod_message = _error_code(lambda: sc.describe_product_as_admin(Id=product_id))
    assert gone_prod == "ResourceNotFoundException", (
        f"DescribeProductAsAdmin after a successful DeleteProduct answered {gone_prod!r}, "
        f"expected 'ResourceNotFoundException'"
    )
    expected = f"There are no local or default products with id {product_id}"
    assert gone_prod_message == expected, f"expected message {expected!r}, got {gone_prod_message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
