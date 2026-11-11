"""put-portal-product-sharing-policy-access-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-portal-product-sharing-policy-access-denied"
GROUP = "overly-permissive"
SERVICES = ["apigatewayv2"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutPortalProductSharingPolicy invoked by a principal with an explicit Deny on
    apigateway:PutPortalProductSharingPolicy is rejected with AccessDeniedException and no policy
    is applied; the unrestricted principal can still set the sharing policy."""
    apigwv2 = ctx.client("apigatewayv2")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    created = apigwv2.create_portal_product(
        DisplayName=ctx.unique_name("sim2real-product-"),
        Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-product-"},
    )
    product_id = created["PortalProductId"]
    product_arn = created["PortalProductArn"]
    ctx.on_cleanup(lambda: apigwv2.delete_portal_product(PortalProductId=product_id))

    policy_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                    "Action": "apigateway:GetPortalProduct",
                    "Resource": product_arn,
                }
            ],
        }
    )

    creds = _create_role_with_explicit_deny(ctx, ["apigateway:PutPortalProductSharingPolicy"])
    restricted_apigwv2 = _restricted_client(ctx, "apigatewayv2", creds)
    restricted_arn = _restricted_client(ctx, "sts", creds).get_caller_identity()["Arn"]

    before_state = _policy_state(apigwv2, product_id)

    err = _error(
        lambda: restricted_apigwv2.put_portal_product_sharing_policy(
            PortalProductId=product_id, PolicyDocument=policy_doc
        )
    )
    expected = (
        "AccessDeniedException",
        f"User: {restricted_arn} is not authorized to perform: "
        f"apigateway:PutPortalProductSharingPolicy on resource: {product_arn} "
        "with an explicit deny in an identity-based policy",
    )
    assert err == expected, f"expected {expected!r}, got {err!r}"

    after_state = _policy_state(apigwv2, product_id)
    assert after_state == before_state, (
        f"sharing policy state changed despite AccessDeniedException: "
        f"before={before_state!r} after={after_state!r}"
    )

    # positive control: the unrestricted principal can set the sharing policy.
    apigwv2.put_portal_product_sharing_policy(PortalProductId=product_id, PolicyDocument=policy_doc)
    ctx.on_cleanup(lambda: _best_effort_delete_sharing_policy(apigwv2, product_id))
    applied = apigwv2.get_portal_product_sharing_policy(PortalProductId=product_id)
    assert json.loads(applied["PolicyDocument"]) == json.loads(policy_doc), (
        f"expected the unrestricted principal's policy to be applied, "
        f"got {applied['PolicyDocument']!r}"
    )


def _policy_state(apigwv2, product_id):
    """Returns a comparable snapshot of the sharing-policy state: either the parsed policy
    document, or the error code if none is set yet (e.g. NotFoundException)."""
    try:
        doc = apigwv2.get_portal_product_sharing_policy(PortalProductId=product_id)["PolicyDocument"]
        return ("ok", json.loads(doc) if doc else doc)
    except ClientError as e:
        return ("error", e.response["Error"]["Code"])

def _best_effort_delete_sharing_policy(apigwv2, product_id):
    try:
        apigwv2.delete_portal_product_sharing_policy(PortalProductId=product_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _error(fn):
    """(code, message) of the ClientError fn raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


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
            Tags=[{"Key": "sim2real:managed", "Value": "true"}],
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
        _wait_for_deny_effective(iam, role_arn, deny_actions)
    except ClientError as e:
        raise AssertionError(
            "insufficient IAM permissions in this environment to create a scoped-deny test role"
        ) from e
    return _assume_role_with_retry(ctx, role_arn)


def _wait_for_deny_effective(iam, role_arn, deny_actions, timeout_s=30.0, interval_s=2.0):
    """IAM's inline-policy write path is eventually consistent: assuming role_arn and calling
    a denied action immediately after put_role_policy can transiently succeed. Poll the
    (non-mutating, advisory-only) policy simulator as a readiness gate before the real,
    enforcement-bearing call is made -- never as the enforcement assertion itself."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        results = iam.simulate_principal_policy(
            PolicySourceArn=role_arn, ActionNames=deny_actions
        )["EvaluationResults"]
        last = {r["EvalActionName"]: r["EvalDecision"] for r in results}
        if all(v == "explicitDeny" for v in last.values()):
            return
        time.sleep(interval_s)
    raise AssertionError(
        f"inline deny policy on {role_arn} for {deny_actions} never became effective within "
        f"{timeout_s}s (last simulated decision={last!r})"
    )


def _assume_role_with_retry(ctx, role_arn, timeout_s=60.0):
    sts = ctx.client("sts")
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return sts.assume_role(RoleArn=role_arn, RoleSessionName="sim2real-behav")["Credentials"]
        except ClientError as e:
            last_err = e
            time.sleep(3)
    raise AssertionError(f"could not assume role {role_arn} in time: {last_err}")


def _restricted_client(ctx, service_name, credentials):
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
