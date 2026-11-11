"""delete-portal-product-access-denied-without-permission."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-portal-product-access-denied-without-permission"
GROUP = "overly-permissive"
SERVICES = ["apigatewayv2"]

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
SESSION_NAME = "sim2real-behav"


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeletePortalProduct invoked by a principal with an explicit Deny on
    apigateway:DeletePortalProduct is rejected with AccessDeniedException, the product remains
    gettable afterward, and the unrestricted principal can still delete it."""
    apigwv2 = ctx.client("apigatewayv2")
    created = apigwv2.create_portal_product(
        DisplayName=ctx.unique_name("sim2real-product-"), Tags=TAGS
    )
    product_id = created["PortalProductId"]
    ctx.on_cleanup(lambda: _best_effort_delete_product(apigwv2, product_id))

    creds, role_name = _create_role_with_explicit_deny(ctx, ["apigateway:DeletePortalProduct"])
    restricted_apigwv2 = _restricted_client(ctx, "apigatewayv2", creds)

    code, message = _error_code(
        lambda: restricted_apigwv2.delete_portal_product(PortalProductId=product_id)
    )
    assert code == "AccessDeniedException", (
        f"expected AccessDeniedException for DeletePortalProduct under an explicit Deny, got {code!r}: {message!r}"
    )
    expected_denied = (
        f"User: arn:aws:sts::{ctx.account}:assumed-role/{role_name}/{SESSION_NAME} is not authorized "
        f"to perform: apigateway:DeletePortalProduct on resource: "
        f"arn:aws:apigateway:{ctx.region}:{ctx.account}:/portalproducts/{product_id} "
        f"with an explicit deny in an identity-based policy"
    )
    assert message == expected_denied, (
        f"unexpected AccessDeniedException message: {message!r} != {expected_denied!r}"
    )

    still_there = apigwv2.get_portal_product(PortalProductId=product_id)
    assert still_there["PortalProductId"] == product_id, (
        f"product {product_id} must still be gettable after the denied delete, "
        f"got {still_there.get('PortalProductId')!r}"
    )

    # positive control: the unrestricted principal can delete the same product.
    apigwv2.delete_portal_product(PortalProductId=product_id)
    code_after_delete, message_after_delete = _error_code(
        lambda: apigwv2.get_portal_product(PortalProductId=product_id)
    )
    assert code_after_delete == "NotFoundException", (
        f"expected NotFoundException reading the deleted product {product_id}, got "
        f"{code_after_delete!r}: {message_after_delete!r}"
    )
    expected_not_found = f"Product not found in account {ctx.account} with id {product_id}"
    assert message_after_delete == expected_not_found, (
        f"unexpected NotFoundException message: {message_after_delete!r} != {expected_not_found!r}"
    )


def _best_effort_delete_product(apigwv2, product_id):
    try:
        apigwv2.delete_portal_product(PortalProductId=product_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _error_code(fn):
    """(code, message) of the captured AWS error. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_role_with_explicit_deny(ctx, deny_actions):
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    try:
        account_id = sts.get_caller_identity()["Account"]
        role_name = ctx.unique_name("sim2real-deny-")
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
        role_arn = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Tags=[{"Key": k, "Value": v} for k, v in TAGS.items()],
        )["Role"]["Arn"]
        ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
        admin_policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
        iam.attach_role_policy(RoleName=role_name, PolicyArn=admin_policy_arn)
        ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=admin_policy_arn))
        deny_policy_name = ctx.unique_name("sim2real-deny-pol-")
        deny_doc = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Deny", "Action": deny_actions, "Resource": "*"}],
        }
        iam.put_role_policy(
            RoleName=role_name, PolicyName=deny_policy_name, PolicyDocument=json.dumps(deny_doc)
        )
        ctx.on_cleanup(
            lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=deny_policy_name)
        )
    except ClientError as e:
        raise AssertionError(
            "insufficient IAM permissions in this environment to create a scoped-deny test role"
        ) from e
    return _assume_role_with_retry(ctx, role_arn), role_name


def _assume_role_with_retry(ctx, role_arn, timeout_s=60.0):
    sts = ctx.client("sts")
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return sts.assume_role(RoleArn=role_arn, RoleSessionName=SESSION_NAME)["Credentials"]
        except ClientError as e:
            last_err = e
            time.sleep(3)
    raise AssertionError(f"could not assume role {role_arn} in time: {last_err}")


def _restricted_client(ctx, service_name, credentials):
    """A client for the same target, signed as the assumed restricted role."""
    return ctx.client(
        service_name,
        creds={
            "aws_access_key_id": credentials["AccessKeyId"],
            "aws_secret_access_key": credentials["SecretAccessKey"],
            "aws_session_token": credentials["SessionToken"],
        },
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
