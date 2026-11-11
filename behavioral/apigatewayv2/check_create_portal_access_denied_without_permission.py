"""create-portal-access-denied-without-permission."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-portal-access-denied-without-permission"
GROUP = "overly-permissive"
SERVICES = ["apigatewayv2"]

_SESSION_NAME = "sim2real-behav"


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreatePortal by a principal with an explicit Deny on apigateway:CreatePortal fails
    AccessDeniedException and creates nothing; that session can still call ListPortals, and an
    unrestricted principal's CreatePortal succeeds."""
    apigwv2 = ctx.client("apigatewayv2")
    creds, role_name = _create_role_with_explicit_deny(ctx, ["apigateway:CreatePortal"])
    restricted_apigwv2 = _restricted_client(ctx, "apigatewayv2", creds)

    display_name = ctx.unique_name("sim2real-portal-denied-")
    portal_content = _portal_content(display_name)

    code, message = _error_code(
        lambda: restricted_apigwv2.create_portal(
            Authorization={"None": {}},
            EndpointConfiguration={"None": {}},
            PortalContent=portal_content,
        )
    )
    assert code == "AccessDeniedException", (
        f"CreatePortal must be rejected with AccessDeniedException for a principal carrying an "
        f"explicit Deny on apigateway:CreatePortal; got {code!r}"
    )
    expected_message = f"User: arn:aws:sts::{ctx.account}:assumed-role/{role_name}/{_SESSION_NAME} is not authorized to perform: apigateway:CreatePortal on resource: arn:aws:apigateway:{ctx.region}:{ctx.account}:/portals/* with an explicit deny in an identity-based policy"
    assert message == expected_message, (
        f"expected the exact message {expected_message!r}, got {message!r}"
    )

    # The denial must be scoped to CreatePortal, not to the whole assumed-role session: a target
    # that blanket-denies a freshly assumed role for an unrelated reason would satisfy the
    # assertion above for the wrong reason. ListPortals is granted by AdministratorAccess and
    # untouched by the Deny, so the same restricted session must still be able to call it.
    sanity = restricted_apigwv2.list_portals()
    assert "Items" in sanity, (
        f"the restricted principal's session must remain functional for an action the Deny does "
        f"not name -- ListPortals must still succeed on the same credentials; got {sanity!r}"
    )

    listing = apigwv2.list_portals()["Items"]
    assert not any(p.get("PortalContent", {}).get("DisplayName") == display_name for p in listing), (
        f"no portal named {display_name!r} must exist after the denied CreatePortal call"
    )

    # positive control: the unrestricted principal can create the same portal.
    created = apigwv2.create_portal(
        Authorization={"None": {}},
        EndpointConfiguration={"None": {}},
        PortalContent=portal_content,
        Tags={"sim2real": CHECK},
    )
    portal_id = created["PortalId"]
    ctx.on_cleanup(lambda: _cleanup_portal(ctx, apigwv2, portal_id))
    fetched = apigwv2.get_portal(PortalId=portal_id)
    assert fetched["PortalContent"]["DisplayName"] == display_name, (
        f"expected the created portal's DisplayName to be {display_name!r}, got "
        f"{fetched['PortalContent'].get('DisplayName')!r}"
    )


def _portal_content(display_name):
    return {
        "DisplayName": display_name,
        "Theme": {
            "CustomColors": {
                "AccentColor": "#0000FF",
                "BackgroundColor": "#FFFFFF",
                "ErrorValidationColor": "#FF0000",
                "HeaderColor": "#111111",
                "NavigationColor": "#222222",
                "TextColor": "#000000",
            }
        },
    }


def _error_code(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises,
    because a target accepting a call real AWS refuses must fail rather than be reported as a
    code mismatch. Throttling is retried."""
    import time

    from botocore.exceptions import ClientError

    for attempt in range(4):
        try:
            result = fn()
        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code")
            if code in ("TooManyRequestsException", "ThrottlingException") and attempt < 3:
                time.sleep(3.0 * (attempt + 1))
                continue
            return code, error.get("Message")
        raise AssertionError(
            f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
        )
    raise AssertionError("unreachable: the loop always returns or raises")


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
            Tags=[{"Key": "sim2real", "Value": CHECK}],
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
            return sts.assume_role(RoleArn=role_arn, RoleSessionName=_SESSION_NAME)["Credentials"]
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


def _cleanup_portal(ctx, apigwv2, portal_id):
    try:
        apigwv2.delete_portal(PortalId=portal_id)
        return
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "NotFoundException":
            return
        if code not in ("ConflictException", "BadRequestException"):
            raise
    try:
        apigwv2.disable_portal(PortalId=portal_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise
    deadline = time.monotonic() + 240
    while time.monotonic() < deadline:
        try:
            status = apigwv2.get_portal(PortalId=portal_id)["PublishStatus"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise
            return
        if status in ("DISABLED", "DISABLE_FAILED"):
            break
        time.sleep(2)
    try:
        apigwv2.delete_portal(PortalId=portal_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
