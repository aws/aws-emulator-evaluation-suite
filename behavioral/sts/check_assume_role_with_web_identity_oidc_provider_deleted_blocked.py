"""assume-role-with-web-identity-oidc-provider-deleted-blocked."""
from __future__ import annotations

import base64
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "assume-role-with-web-identity-oidc-provider-deleted-blocked"
GROUP = "overly-permissive"
SERVICES = ["sts"]

# Marks a failure where the target accepted a resource that never reached its ready state, so it
# reads as a state-machine failure and not as a connection or not-implemented error.
STATE_MARKER = "TARGET_STATE_UNIMPLEMENTED"


def _never_ready(msg: str):
    """The verdict for a resource that never reached its ready state.

    Returns the exception rather than raising it, so a call site keeps its ``from exc`` chaining.
    """
    return AssertionError(f"{STATE_MARKER}: {msg}")


# The token is a well-formed JWT with a placeholder signature: AWS validates signatures
# against the issuer's public JWKS, which the check cannot serve.
# example.com (RFC 2606) serves valid HTTPS, so CreateOpenIDConnectProvider accepts it as issuer.
_ISSUER_HOST = "example.com"


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A forged web identity token stays rejected after its role's OIDC provider is deleted, with
    exactly the rejection it got while the provider existed (STS does not reveal the removal), and
    still exactly that rejection once the provider is recreated under the same ARN.
    """
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    # Unique path component keeps this account's provider URL distinct across
    # runs/checks; IAM only needs to reach the host to fetch its TLS cert
    # chain thumbprint, so a nonexistent path is fine.
    issuer_url = f"https://{_ISSUER_HOST}/{ctx.unique_name('oidc')}"
    audience = "sim2real-aud-test"

    def _create_provider() -> str:
        try:
            return iam.create_open_id_connect_provider(
                Url=issuer_url,
                ClientIDList=[audience],
                ThumbprintList=["0" * 40],
                Tags=[{"Key": "sim2real-check", "Value": CHECK}],
            )["OpenIDConnectProviderArn"]
        except ClientError as exc:
            raise AssertionError(
                f"CreateOpenIDConnectProvider against the real public issuer host "
                f"failed unexpectedly ({exc.response['Error']['Code']}); cannot "
                "establish the provider-present state this check depends on"
            )

    provider_arn = _create_provider()
    ctx.on_cleanup(lambda: _delete_oidc_provider(iam, provider_arn))

    role_name = ctx.unique_name("sim2real-oidcrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Federated": provider_arn},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringEquals": {f"{_ISSUER_HOST}:aud": audience}
                },
            }
        ],
    }
    role_arn = _create_role_with_retry(iam, role_name, trust_policy)
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))


    token = _build_unsigned_jwt(issuer_url, audience)

    def _attempt_detail() -> tuple[str, str]:
        try:
            sts.assume_role_with_web_identity(
                RoleArn=role_arn,
                RoleSessionName="sim2real-oidc-session",
                WebIdentityToken=token,
            )
            return "SUCCESS", ""
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")

    # Provider present: AWS rejects the forged token on content or communication
    # grounds. Role-trust propagation can lag a few seconds after CreateRole, so poll
    # for the steady state. Real STS reports the shape's code (InvalidIdentityToken).
    _non_principal_codes = ("InvalidIdentityToken", "IDPCommunicationError")
    present = _poll_until(
        _attempt_detail,
        lambda d: d[0] in _non_principal_codes,
        timeout_s=60.0,
        interval_s=2.0,
    )
    if present[0] not in _non_principal_codes:
        raise _never_ready(
            "the provider-present control call never settled on a "
            f"token-content/communication error (last observed {present!r}); "
            "this environment's STS did not reject the forged token the way "
            "this check expects",
        )

    # Break exactly one thing: delete the OIDC provider the role trusts.
    iam.delete_open_id_connect_provider(OpenIDConnectProviderArn=provider_arn)

    # Independent read: the deleted provider is actually gone.
    try:
        iam.get_open_id_connect_provider(OpenIDConnectProviderArn=provider_arn)
        raise AssertionError(
            "GetOpenIDConnectProvider unexpectedly succeeded for a provider "
            "this check just deleted"
        )
    except ClientError as exc:
        assert exc.response["Error"]["Code"] == "NoSuchEntity", (
            f"expected NoSuchEntity reading the deleted provider, got "
            f"{exc.response['Error']['Code']!r}"
        )
        assert exc.response["Error"].get("Message") == (
            f"OpenIDConnect Provider not found for arn {provider_arn}"
        ), exc.response["Error"].get("Message")

    deleted = _attempt_detail()
    assert deleted == present, (
        f"expected the same rejection with the provider deleted as with it present "
        f"({present!r}), got {deleted!r}"
    )

    # Restore: the provider's ARN is derived from its URL, so recreating it restores the
    # exact ARN the role's trust policy names; the forged token is still rejected the same way.
    restored_arn = _create_provider()
    assert restored_arn == provider_arn, (
        f"recreating the OIDC provider under the same URL produced a different "
        f"ARN ({restored_arn!r} != {provider_arn!r})"
    )
    restored = _attempt_detail()
    assert restored == present, (
        f"expected the provider-present rejection once the provider was recreated "
        f"({present!r}), got {restored!r}"
    )


# ===== helpers =====


def _build_unsigned_jwt(issuer: str, audience: str) -> str:
    """A syntactically valid JWT (header.payload.signature) with a throwaway
    signature. Real AWS never reaches signature verification in either branch
    of this check (network fetch fails first while the provider exists; the
    principal doesn't resolve at all once it's deleted), so the signature
    content itself is never the thing under test."""
    header = {"alg": "RS256", "typ": "JWT"}
    now = int(time.time())
    payload = {
        "iss": issuer,
        "aud": audience,
        "sub": "sim2real-subject",
        "iat": now,
        "exp": now + 3600,
    }
    encoded = ".".join(
        _b64url(json.dumps(part, separators=(",", ":")).encode("utf-8"))
        for part in (header, payload)
    )
    signature = _b64url(b"sim2real-placeholder-signature")
    return f"{encoded}.{signature}"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _poll_until(probe, predicate, timeout_s: float = 30.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result) and time.monotonic() < deadline:
        time.sleep(interval_s)
        result = probe()
    return result


def _create_role_with_retry(
    iam, role_name: str, trust_policy: dict, timeout_s: float = 30.0, interval_s: float = 2.0
) -> str:
    """CreateRole can reject a just-created OIDC provider's ARN as an unknown
    trusted principal for a brief window while the provider propagates
    through IAM; retry MalformedPolicyDocument until it clears."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return iam.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(trust_policy),
                Tags=[{"Key": "sim2real-check", "Value": CHECK}],
            )["Role"]["Arn"]
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "")
            if code != "MalformedPolicyDocument" or time.monotonic() >= deadline:
                raise AssertionError(
                    f"CreateRole rejected the OIDC-provider trust policy "
                    f"({code}): {message}"
                ) from exc
            time.sleep(interval_s)


def _delete_oidc_provider(iam, arn: str) -> None:
    try:
        iam.delete_open_id_connect_provider(OpenIDConnectProviderArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_role(iam, name: str) -> None:
    try:
        iam.delete_role(RoleName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
