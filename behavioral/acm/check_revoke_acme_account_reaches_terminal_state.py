"""revoke-acme-account-reaches-terminal-state."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "revoke-acme-account-reaches-terminal-state"
GROUP = "state-machine"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """RevokeAcmeAccount moves the account to a terminal REVOKED status reflected by
    DescribeAcmeAccount, not resource removal. The account is registered for real, over the
    RFC 8555 ACME protocol, against the endpoint's live directory URL."""
    import josepy as jose  # noqa: F401
    from acme import client as acme_client  # noqa: F401
    from acme import messages as acme_messages  # noqa: F401
    from cryptography.hazmat.primitives.asymmetric import ec  # noqa: F401

    acm = ctx.client("acm")
    endpoint_arn, endpoint_url = _create_active_endpoint(ctx, acm)
    role_arn = _create_acme_eab_role(ctx)
    eab = _create_binding(ctx, acm, endpoint_arn, role_arn)["ExternalAccountBinding"]
    eab_arn = eab["AcmeExternalAccountBindingArn"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: acm.delete_acme_external_account_binding(AcmeExternalAccountBindingArn=eab_arn))
    )
    creds = acm.get_acme_external_account_binding_credentials(AcmeExternalAccountBindingArn=eab_arn)

    account_url = _register_acme_account(endpoint_url, creds["KeyId"], creds["MacKey"])

    account = _poll_until(
        lambda: acm.describe_acme_account(AcmeEndpointArn=endpoint_arn, AccountUrl=account_url)["AcmeAccount"],
        lambda a: a["Status"] in ("VALID", "DEACTIVATED", "REVOKED"),
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert account["Status"] == "VALID", f"newly registered account was not VALID: {account}"
    assert account["AccountUrl"] == account_url, (
        f"describe returned a different AccountUrl than registration: "
        f"expected {account_url}, got {account['AccountUrl']}"
    )

    acm.revoke_acme_account(AcmeEndpointArn=endpoint_arn, AccountUrl=account_url)

    revoked = _poll_until(
        lambda: acm.describe_acme_account(AcmeEndpointArn=endpoint_arn, AccountUrl=account_url)["AcmeAccount"],
        lambda a: a["Status"] == "REVOKED",
        timeout_s=30.0,
        interval_s=2.0,
    )
    # Terminal state, not resource removal: the account is still describable with the same URL.
    assert revoked["Status"] == "REVOKED", f"expected terminal REVOKED, got {revoked['Status']}"
    assert revoked["AccountUrl"] == account_url, (
        f"post-revoke describe returned a different AccountUrl: expected {account_url}, "
        f"got {revoked['AccountUrl']}"
    )


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _succeeds(fn) -> bool:
    """Whether fn returns without a ClientError."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError:
        return False
    return True


def _ignore_not_found(fn):
    """Run a teardown delete; only an already-gone resource is tolerated."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_binding(ctx, acm, endpoint_arn, role_arn):
    """CreateAcmeExternalAccountBinding, retried on the PassRole AccessDeniedException a fresh role returns while IAM propagates."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + min(60.0, ctx.time_left())
    while True:
        try:
            return acm.create_acme_external_account_binding(AcmeEndpointArn=endpoint_arn, RoleArn=role_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() >= deadline:
                raise
        time.sleep(2.0)


def _create_active_endpoint(ctx, acm):
    resp = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        Contact="NOT_REQUIRED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
        Tags=[{"Key": "sim2real-check", "Value": ctx.unique_name("revoke-acme-account-")}],
    )
    arn = resp["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=arn)))
    endpoint = _poll_until(
        lambda: acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"],
        lambda ep: ep["Status"] in ("ACTIVE", "FAILED"),
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert endpoint["Status"] == "ACTIVE", f"endpoint did not reach ACTIVE: {endpoint}"
    return arn, endpoint["EndpointUrl"]


def _create_acme_eab_role(ctx):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-acme-eab-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "acm-acme.amazonaws.com"},
                "Action": ["sts:AssumeRole", "sts:TagSession", "sts:SetSourceIdentity"],
                "Condition": {"StringLikeIfExists": {"sts:SourceIdentity": "acm-acme-*"}},
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real-check", "Value": name}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: iam.delete_role(RoleName=name)))
    _poll_until(lambda: _succeeds(lambda: iam.get_role(RoleName=name)), lambda ok: ok, timeout_s=20.0, interval_s=1.0)
    return role_arn


def _register_acme_account(directory_url: str, key_id: str, mac_key: str) -> str:
    """Registers a brand-new ACME account (RFC 8555 newAccount, with external account
    binding) against a live ACME directory, and returns the account's URL (kid)."""
    import josepy as jose
    from acme import client as acme_client
    from acme import messages as acme_messages
    from cryptography.hazmat.primitives.asymmetric import ec

    account_key = jose.JWKEC(key=ec.generate_private_key(ec.SECP256R1()))
    net = acme_client.ClientNetwork(account_key, alg=jose.ES256, user_agent="sim2real-acm-behavioral-check/1.0")
    directory = acme_messages.Directory.from_json(net.get(directory_url).json())
    client_v2 = acme_client.ClientV2(directory, net)
    eab = acme_messages.ExternalAccountBinding.from_data(
        account_public_key=account_key.public_key(),
        kid=key_id,
        hmac_key=mac_key,
        directory=directory,
    )
    new_reg = acme_messages.NewRegistration.from_data(terms_of_service_agreed=True, external_account_binding=eab)
    registration = client_v2.new_account(new_reg)
    return registration.uri


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
