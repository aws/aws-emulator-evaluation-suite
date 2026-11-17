"""role-trust-aud-condition-rejects-a-sibling-clients-token."""
from __future__ import annotations

import base64
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "role-trust-aud-condition-rejects-a-sibling-clients-token"
GROUP = "web-identity-federation"
SERVICES = ["cognito-idp", "iam", "sts"]

#: Bounded convergence for the freshly created OIDC provider and role trust to become usable.
_PROPAGATE_S = 180.0


def _jwt_claims(token: str) -> dict:
    """The JSON claims carried in a JWT's payload segment."""
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


def _issuer_without_scheme(issuer: str) -> str:
    assert issuer.startswith("https://"), f"issuer {issuer!r} must be an https URL"
    return issuer[len("https://"):]


def _err(exc: ClientError) -> tuple[str, str]:
    e = exc.response.get("Error", {})
    return e.get("Code") or "", e.get("Message") or ""


def _error(fn) -> tuple[str, str]:
    """(code, message) of the ClientError ``fn()`` raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        return _err(exc)
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _assume_with_retry(sts, expected_denial: tuple[str, str], **kwargs) -> dict:
    """AssumeRoleWithWebIdentity, retrying only the exact denial IAM propagation produces."""
    deadline = time.monotonic() + _PROPAGATE_S
    while True:
        try:
            return sts.assume_role_with_web_identity(**kwargs)
        except ClientError as exc:
            pair = _err(exc)
            if pair != expected_denial or time.monotonic() >= deadline:
                raise
            time.sleep(3.0)


def _mint(idp, pool_id: str, client_id: str, username: str, password: str) -> str:
    return idp.admin_initiate_auth(
        UserPoolId=pool_id, ClientId=client_id, AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )["AuthenticationResult"]["IdToken"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A role's AssumeRoleWithWebIdentity trust condition pins the issuer's `aud` to one app
    client; a second client's token, though the IAM OIDC provider's ClientIDList admits both,
    is refused AccessDenied while the pinned client's own token still assumes the role.
    """
    idp = ctx.client("cognito-idp")
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-xsvc-audtrust-up-"),
        UserPoolTags={"sim2real": CHECK},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    trusted_client = idp.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-xsvc-audtrust-trusted-"),
        GenerateSecret=False, ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH"],
    )["UserPoolClient"]["ClientId"]
    sibling_client = idp.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-xsvc-audtrust-sibling-"),
        GenerateSecret=False, ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH"],
    )["UserPoolClient"]["ClientId"]

    username = ctx.unique_name("sim2real-xsvc-audtrust-user-")
    password = "Sim2Real!" + username[-12:]
    idp.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    ctx.on_cleanup(lambda: idp.admin_delete_user(UserPoolId=pool_id, Username=username))
    idp.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=password, Permanent=True,
    )

    trusted_token = _mint(idp, pool_id, trusted_client, username, password)
    sibling_token = _mint(idp, pool_id, sibling_client, username, password)
    issuer = _jwt_claims(trusted_token)["iss"]
    assert _jwt_claims(sibling_token)["iss"] == issuer, "both clients must share one user pool issuer"
    issuer_key = _issuer_without_scheme(issuer)

    # The provider admits BOTH clients: the scoping under test is the role's own condition.
    provider_arn = iam.create_open_id_connect_provider(
        Url=issuer, ClientIDList=[trusted_client, sibling_client],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["OpenIDConnectProviderArn"]
    ctx.on_cleanup(lambda: iam.delete_open_id_connect_provider(OpenIDConnectProviderArn=provider_arn))
    stored_clients = sorted(
        iam.get_open_id_connect_provider(OpenIDConnectProviderArn=provider_arn)["ClientIDList"]
    )
    assert stored_clients == sorted([trusted_client, sibling_client]), (
        f"ClientIDList: expected both clients, got {stored_clients!r}"
    )

    role_name = ctx.unique_name("sim2real-xsvc-audtrust-role-")[:64]
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Federated": provider_arn},
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {"StringEquals": {f"{issuer_key}:aud": trusted_client}},
        }],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    propagation_denial = ("AccessDenied", "Not authorized to perform sts:AssumeRoleWithWebIdentity")

    # Positive control: the client the trust condition names assumes the role, and this also
    # absorbs the new role/provider's propagation lag before the refusal below is asserted.
    control_session = ctx.unique_name("audtrust-control-")
    control = _assume_with_retry(
        sts, propagation_denial, RoleArn=role_arn, RoleSessionName=control_session,
        WebIdentityToken=trusted_token,
    )
    want_control_arn = f"arn:aws:sts::{ctx.account}:assumed-role/{role_name}/{control_session}"
    assert control["AssumedRoleUser"]["Arn"] == want_control_arn, (
        f"control AssumedRoleUser.Arn: expected {want_control_arn!r}, got "
        f"{control['AssumedRoleUser']['Arn']!r}"
    )

    # The one difference: a sibling client's token, same issuer, same provider's ClientIDList,
    # but not the audience the role's own condition names.
    sibling_session = ctx.unique_name("audtrust-sibling-")
    code, message = _error(lambda: sts.assume_role_with_web_identity(
        RoleArn=role_arn, RoleSessionName=sibling_session, WebIdentityToken=sibling_token,
    ))
    assert code == "AccessDenied", f"expected AccessDenied for the sibling client, got {code!r}: {message!r}"
    assert message == "Not authorized to perform sts:AssumeRoleWithWebIdentity", (
        f"unexpected message {message!r}"
    )

    # The refusal is stable, not a one-off propagation artifact.
    code_again, message_again = _error(lambda: sts.assume_role_with_web_identity(
        RoleArn=role_arn, RoleSessionName=sibling_session, WebIdentityToken=sibling_token,
    ))
    assert (code_again, message_again) == (code, message), (
        f"repeat refusal {(code_again, message_again)!r} must match the first {(code, message)!r}"
    )

    # The trusted client still assumes the role: the sibling's refusal narrowed nothing else.
    again_session = ctx.unique_name("audtrust-again-")
    again = sts.assume_role_with_web_identity(
        RoleArn=role_arn, RoleSessionName=again_session, WebIdentityToken=trusted_token,
    )
    want_again_arn = f"arn:aws:sts::{ctx.account}:assumed-role/{role_name}/{again_session}"
    assert again["AssumedRoleUser"]["Arn"] == want_again_arn, (
        f"trusted client after the sibling's refusal: expected {want_again_arn!r}, got "
        f"{again['AssumedRoleUser']['Arn']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
