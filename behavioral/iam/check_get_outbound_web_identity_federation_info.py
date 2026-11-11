"""get-outbound-web-identity-federation-info."""
from __future__ import annotations

import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-outbound-web-identity-federation-info"
GROUP = 'web_identity_federation'
SERVICES = ['iam']


def _no_policy_denial(user_arn: str, action: str) -> re.Pattern:
    """AWS's refusal of ``user_arn``, which no policy grants ``action``; it ends with a per-request
    authorization id, given twice (in a console URL and on its own)."""
    return re.compile(
        rf"User: {re.escape(user_arn)} is not authorized to perform: iam:{action} on resource: \* "
        rf"because no identity-based policy allows the iam:{action} action\. Go to "
        r"https://[a-z0-9-]+\.console\.aws\.amazon\.com/iam/home\?region=[a-z0-9-]+"
        r"#/authorization-details/(\w+) for complete details, or call the GetRequestAuthorizationDetails "
        r"API with the following authorization id: \1"
    )


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. Raises if fn()
    succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _unprivileged_client(ctx):
    """A new zero-permission IAM user with an access key, returned as (IAM client for that user, its ARN).
    Access-key propagation is not instant, so STS is polled until the key is recognized."""
    iam = ctx.client("iam")
    user_name = ctx.unique_name("nopriv-")
    user_arn = iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])["User"]["Arn"]

    def _cleanup():
        try:
            for k in iam.list_access_keys(UserName=user_name)["AccessKeyMetadata"]:
                iam.delete_access_key(UserName=user_name, AccessKeyId=k["AccessKeyId"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_user(UserName=user_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    created = iam.create_access_key(UserName=user_name)["AccessKey"]
    creds = {
        "aws_access_key_id": created["AccessKeyId"],
        "aws_secret_access_key": created["SecretAccessKey"],
    }
    unpriv_sts = ctx.client("sts", creds=creds)
    # Bounded by the runner's remaining time, so a key that never authenticates fails here.
    budget_s = max(1.0, min(60.0, (ctx.time_left() or 60.0) - 5.0))
    deadline = time.monotonic() + budget_s
    while True:
        try:
            unpriv_sts.get_caller_identity()
            break
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in (
                "InvalidClientTokenId",
                "InvalidAccessKeyId",
            ):
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(f"minted access key was not recognized within {budget_s:.0f}s") from exc
            time.sleep(3)
    return ctx.client("iam", creds=creds), user_arn


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:iam-outbound-web-identity-federation")
def run(ctx) -> None:
    """GetOutboundWebIdentityFederationInfo is rejected FeatureDisabled while the feature is off
    and, once enabled, returns an https IssuerIdentifier with JwtVendingEnabled True; a
    zero-permission caller is rejected AccessDenied."""
    iam = ctx.client("iam")
    try:
        iam.get_outbound_web_identity_federation_info()
        disabled_code = None
    except ClientError as exc:
        disabled_code = exc.response.get("Error", {}).get("Code")
    if disabled_code == "FeatureDisabled":
        iam.enable_outbound_web_identity_federation()
        ctx.on_cleanup(lambda: iam.disable_outbound_web_identity_federation())
    elif disabled_code is not None:
        raise AssertionError(f"unexpected error before enabling the feature: {disabled_code}")

    info = iam.get_outbound_web_identity_federation_info()
    assert info.get("JwtVendingEnabled") is True, (
        f"expected JwtVendingEnabled=True once enabled, got {info}"
    )
    assert info.get("IssuerIdentifier", "").startswith("https://"), (
        f"expected an https issuer URL, got {info}"
    )

    unpriv, unpriv_arn = _unprivileged_client(ctx)
    code, message = _error(lambda: unpriv.get_outbound_web_identity_federation_info())
    assert code == "AccessDenied", f"expected AccessDenied for a zero-permission caller, got {code}"
    # Only the authorization id AWS appends varies per call.
    assert _no_policy_denial(unpriv_arn, "GetOutboundWebIdentityFederationInfo").fullmatch(message), (
        f"expected AWS's no-policy denial of iam:GetOutboundWebIdentityFederationInfo; got {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
