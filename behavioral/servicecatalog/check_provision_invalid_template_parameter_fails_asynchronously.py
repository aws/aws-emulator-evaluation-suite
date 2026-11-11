"""provision-invalid-template-parameter-fails-asynchronously."""
from __future__ import annotations

import json
import re
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "provision-invalid-template-parameter-fails-asynchronously"
GROUP = 'provisioning'
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


def _error_code(fn) -> str:
    """The botocore Error.Code and Error.Message raised by fn(). An unexpected SUCCESS raises rather than returning a
    falsy sentinel: an emulator that publishes outputs for a launch that never deployed is the
    strongest signal this check can produce and must not be reported as a code mismatch."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("the call was expected to fail on real AWS but succeeded")


def _without_request_id(text):
    """``text`` with CloudFormation's embedded request id replaced by ``<id>``."""
    return re.sub(r"Request ID: [0-9a-f-]+;", "Request ID: <id>;", text or "")


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
    """Terminate and WAIT. DeleteProduct is registered earlier in the LIFO chain and fails while a
    provisioned product still references the product, so returning early strands both. IgnoreErrors
    is required here because one of the two products under test is in ERROR."""
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
    """ProvisionProduct with a value outside the template's AllowedValues is accepted (CREATED) but
    settles at ERROR with a FAILED record carrying the exact reason and publishes no outputs
    (InvalidParametersException); the same launch with a legal value reaches AVAILABLE."""
    sc, who, _ = _launch_principal(ctx)
    s3 = ctx.client("s3")

    product_id, artifact_id, path_id = _launch_path(ctx, sc, s3, who)

    # The template constrains Env to dev|prod; break exactly that one thing.
    declared = sc.describe_provisioning_parameters(
        ProductId=product_id, ProvisioningArtifactId=artifact_id, PathId=path_id)
    allowed = [p["ParameterConstraints"]["AllowedValues"]
               for p in declared["ProvisioningArtifactParameters"] if p["ParameterKey"] == "Env"]
    assert allowed == [["dev", "prod"]], (
        f"Service Catalog reported Env's AllowedValues as {allowed!r}, expected [['dev', 'prod']] "
        f"— it did not parse the template's own constraint"
    )

    bad = sc.provision_product(
        ProductId=product_id, ProvisioningArtifactId=artifact_id, PathId=path_id,
        ProvisionedProductName=ctx.unique_name("sim2real-sc-pp-"),
        ProvisionToken=uuid.uuid4().hex,
        ProvisioningParameters=[{"Key": "Env", "Value": "staging"}],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["RecordDetail"]
    bad_pp = bad["ProvisionedProductId"]
    ctx.on_cleanup(lambda: _terminate(sc, bad_pp))

    # Synchronously ACCEPTED — an emulator that rejects here is wrong in the other direction.
    assert bad["Status"] == "CREATED", (
        f"ProvisionProduct answered record status {bad['Status']!r} for an out-of-range parameter, "
        f"expected 'CREATED' — real AWS accepts the request and fails the deploy"
    )
    assert bad["RecordErrors"] == [], (
        f"the accepted record already carried errors {bad['RecordErrors']!r}, expected none at "
        f"request time"
    )

    # ...and asynchronously REFUSED, with the reason attached to the record.
    bad_detail = _await_settled(sc, bad_pp, deadline=240.0)
    assert bad_detail["Status"] == "ERROR", (
        f"the out-of-range launch settled at {bad_detail['Status']!r}, expected 'ERROR'"
    )
    bad_record = sc.describe_record(Id=bad_detail["LastRecordId"])["RecordDetail"]
    assert bad_record["Status"] == "FAILED", (
        f"the failed launch's record is {bad_record['Status']!r}, expected 'FAILED'"
    )
    # CloudFormation's text embeds its own per-call request id; only that token is normalised.
    expected = (
        "AmazonCloudFormationException  Parameter 'Env' must be one of AllowedValues (Service: "
        "AmazonCloudFormation; Status Code: 400; Error Code: ValidationError; Request ID: <id>; "
        "Proxy: null)"
    )
    status_message = _without_request_id(bad_detail.get("StatusMessage"))
    assert status_message == expected, (
        f"the errored provisioned product's StatusMessage is {bad_detail.get('StatusMessage')!r}, "
        f"expected {expected!r}"
    )
    descriptions = [_without_request_id(e.get("Description")) for e in bad_record["RecordErrors"]]
    expected = [expected]
    assert descriptions == expected, (
        f"the record's errors are {bad_record['RecordErrors']!r}, expected descriptions {expected!r}"
    )

    # The effect is ABSENT: nothing was deployed, so there are no outputs to publish — and real AWS
    # refuses the question rather than answering it with an empty list.
    outputs_code, outputs_message = _error_code(
        lambda: sc.get_provisioned_product_outputs(ProvisionedProductId=bad_pp))
    assert outputs_code == "InvalidParametersException", (
        f"GetProvisionedProductOutputs on the errored provisioned product answered "
        f"{outputs_code!r}, expected 'InvalidParametersException' — no successful provisioning "
        f"record exists, so there is no stack to expose"
    )
    expected = "Last Successful Provisioning Record doesn't exist."
    assert outputs_message == expected, f"expected message {expected!r}, got {outputs_message!r}"

    # ---- positive control: the same launch, one legal value ----
    good = sc.provision_product(
        ProductId=product_id, ProvisioningArtifactId=artifact_id, PathId=path_id,
        ProvisionedProductName=ctx.unique_name("sim2real-sc-pp-"),
        ProvisionToken=uuid.uuid4().hex,
        ProvisioningParameters=[{"Key": "Env", "Value": "prod"}],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["RecordDetail"]
    good_pp = good["ProvisionedProductId"]
    ctx.on_cleanup(lambda: _terminate(sc, good_pp))

    good_detail = _await_settled(sc, good_pp, deadline=240.0)
    assert good_detail["Status"] == "AVAILABLE", (
        f"the in-range launch settled at {good_detail['Status']!r} "
        f"({good_detail.get('StatusMessage')!r}), expected 'AVAILABLE'"
    )
    good_outputs = {o["OutputKey"]: o["OutputValue"] for o in
                    sc.get_provisioned_product_outputs(ProvisionedProductId=good_pp)["Outputs"]}
    assert good_outputs.get("EnvEcho") == "prod", (
        f"the accepted launch's EnvEcho output is {good_outputs.get('EnvEcho')!r}, expected 'prod'"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
