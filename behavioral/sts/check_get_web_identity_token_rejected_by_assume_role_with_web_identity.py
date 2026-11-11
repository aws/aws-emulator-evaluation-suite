"""get-web-identity-token-rejected-by-assume-role-with-web-identity."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-web-identity-token-rejected-by-assume-role-with-web-identity"
GROUP = "data-plane"
SERVICES = ["sts"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control", "resource:account-singleton:iam-outbound-web-identity-federation")
def run(ctx) -> None:
    """GetWebIdentityToken JWTs are outbound-only: IAM refuses the issuer as an OIDC provider
    (InvalidInput) and AssumeRoleWithWebIdentity refuses the token (InvalidIdentityToken),
    each with its exact message, while plain AssumeRole on the same role succeeds.
    """
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    issuer = _ensure_outbound_federation_enabled(ctx, iam)
    audience = "https://sim2real.example.com/webid-rejection-check"

    account_id = sts.get_caller_identity()["Account"]
    resource_tags = [
        {"Key": "sim2real:managed", "Value": "true"},
        {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
    ]

    # Refusal 1: the issuer cannot be registered as an inbound OIDC provider.
    def _create_provider():
        arn = iam.create_open_id_connect_provider(
            Url=issuer, ClientIDList=[audience], Tags=resource_tags
        )["OpenIDConnectProviderArn"]
        ctx.on_cleanup(lambda: iam.delete_open_id_connect_provider(OpenIDConnectProviderArn=arn))
        return arn

    provider_code, provider_message = _refusal(_create_provider)
    assert provider_code == "InvalidInput", (
        f"expected InvalidInput registering the outbound issuer as an OIDC provider, "
        f"got {provider_code!r}"
    )
    expected_provider_message = (
        "Creating an OIDC provider with an STS issuer URL from the same partition is not "
        "supported. Within a partition, use AssumeRole instead of web identity federation."
    )
    assert provider_message == expected_provider_message, (
        f"expected the refusal message {expected_provider_message!r}, got {provider_message!r}"
    )

    role_name = ctx.unique_name("sim2real-behav-webid-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowPlainAssumeRole",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            },
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=resource_tags,
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    # Positive control: the role is assumable (trust propagation takes a few seconds).
    control_creds = _wait_for_assume_role(
        sts, RoleArn=role_arn, RoleSessionName="control-session"
    )
    assert control_creds["AccessKeyId"], (
        "positive control: plain AssumeRole against the same role must succeed and "
        f"return credentials, got {control_creds!r}"
    )

    token = _poll_settled(
        lambda: _try_mint(sts, audience), lambda r: r is not None
    )["WebIdentityToken"]

    # Refusal 2: the token itself is not accepted for inbound federation.
    code, message = _refusal(
        lambda: sts.assume_role_with_web_identity(
            RoleArn=role_arn,
            RoleSessionName="webid-rejection-session",
            WebIdentityToken=token,
        )
    )
    assert code == "InvalidIdentityToken", f"expected InvalidIdentityToken, got {code!r}"
    expected_message = "AssumeRoleWithWebIdentity with STS-issued tokens is not yet supported."
    assert message == expected_message, (
        f"expected the refusal message {expected_message!r}, got {message!r}"
    )


def _ensure_outbound_federation_enabled(ctx, iam) -> str:
    try:
        info = iam.enable_outbound_web_identity_federation()
        issuer = info["IssuerIdentifier"]
        ctx.on_cleanup(lambda: _safe_disable_federation(iam))
    except ClientError as err:
        if err.response["Error"]["Code"] != "FeatureEnabled":
            raise
        issuer = iam.get_outbound_web_identity_federation_info()["IssuerIdentifier"]
    return issuer


def _poll_settled(probe, predicate, *, times: int = 3, timeout_s: float = 60.0,
                  interval_s: float = 2.0):
    """The last of `times` CONSECUTIVE probe results that satisfy predicate. The account-level
    federation flag reaches STS replicas unevenly, so one observation does not mean it settled."""
    deadline = time.monotonic() + timeout_s
    streak, last = 0, None
    while True:
        last = probe()
        streak = streak + 1 if predicate(last) else 0
        if streak >= times:
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"no {times} consecutive matching results within {timeout_s}s (last={last!r})"
            )
        time.sleep(interval_s)


def _try_mint(sts, audience):
    """A minted token, or None while the account's enable has not reached this replica."""
    try:
        return sts.get_web_identity_token(
            Audience=[audience], SigningAlgorithm="RS256", DurationSeconds=300
        )
    except ClientError as err:
        if err.response["Error"]["Code"] == "OutboundWebIdentityFederationDisabledException":
            return None
        raise


def _safe_disable_federation(iam) -> None:
    try:
        iam.disable_outbound_web_identity_federation()
    except ClientError as err:
        if err.response["Error"]["Code"] != "FeatureDisabled":
            raise


def _wait_for_assume_role(sts_client, timeout_s: float = 30.0, interval_s: float = 2.0, **kwargs):
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return sts_client.assume_role(**kwargs)["Credentials"]
        except ClientError as err:
            if err.response["Error"]["Code"] != "AccessDenied":
                raise
            last_err = err
            time.sleep(interval_s)
    raise AssertionError(f"assume_role never became permitted within {timeout_s}s: {last_err}")


def _refusal(fn):
    """The (code, message) of a refused call; raises when the call succeeds."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
