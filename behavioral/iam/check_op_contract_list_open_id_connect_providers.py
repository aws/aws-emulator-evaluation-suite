"""op-contract-list-open-id-connect-providers."""
from __future__ import annotations

import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-list-open-id-connect-providers"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c7", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListOpenIDConnectProviders lists a freshly created provider; a zero-permission principal
    gets the exact implicit-deny AccessDenied (the op takes no input, so no validation boundary);
    the denied call leaves the creator's view unaffected."""
    iam = ctx.client("iam")

    oidc_url = f"https://{ctx.unique_name('sim2real-oidc-')}.example.com"
    provider_arn = iam.create_open_id_connect_provider(
        Url=oidc_url,
        ThumbprintList=["0" * 40],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["OpenIDConnectProviderArn"]
    ctx.on_cleanup(lambda: iam.delete_open_id_connect_provider(OpenIDConnectProviderArn=provider_arn))

    resp = iam.list_open_id_connect_providers()
    arns = [p["Arn"] for p in resp["OpenIDConnectProviderList"]]
    assert provider_arn in arns, f"{provider_arn} missing from ListOpenIDConnectProviders: {arns}"

    # Authorization boundary: a brand-new IAM user with zero attached policies is
    # implicit-denied on any API call, including this parameterless list op.
    user_name = ctx.unique_name("sim2real-behav-denied-")
    user_arn = iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])["User"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    key = iam.create_access_key(UserName=user_name)["AccessKey"]
    ctx.on_cleanup(lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=key["AccessKeyId"]))

    denied_client = ctx.client(
        "iam",
        creds={
            "aws_access_key_id": key["AccessKeyId"],
            "aws_secret_access_key": key["SecretAccessKey"],
        },
    )
    code, denied_msg = _wait_for_denied(denied_client, timeout_s=30.0)
    # The implicit-deny message ends with a per-request authorization id (in the console link and
    # the GetRequestAuthorizationDetails pointer). The id is read from the message; every other
    # character of the expected message is built from values the check created.
    partition = user_arn.split(":")[1]
    authz = re.search(r"authorization id: ([A-Za-z0-9]+)$", denied_msg or "")
    authz_id = authz.group(1) if authz else "<no authorization id>"
    expected_denial = (
        f"User: {user_arn} is not authorized to perform: iam:ListOpenIDConnectProviders on "
        f"resource: arn:{partition}:iam::{ctx.account}:oidc-provider/* because no identity-based "
        f"policy allows the iam:ListOpenIDConnectProviders action. Go to "
        f"https://us-east-1.console.aws.amazon.com/iam/home?region=us-east-1#/authorization-details/"
        f"{authz_id} for complete details, or call the GetRequestAuthorizationDetails API with the "
        f"following authorization id: {authz_id}"
    )
    assert denied_msg == expected_denial, (
        f"expected the implicit denial {expected_denial!r}; got {denied_msg!r}"
    )
    assert code == "AccessDenied", f"expected access-denied, got {code}"

    # Positive control, repeated: the denied excursion had no side effect on the
    # original principal's own view of the provider it created.
    resp2 = iam.list_open_id_connect_providers()
    arns2 = [p["Arn"] for p in resp2["OpenIDConnectProviderList"]]
    assert provider_arn in arns2, f"{provider_arn} missing after denied excursion: {arns2}"


def _wait_for_denied(client, timeout_s: float = 30.0, interval_s: float = 2.0):
    """Poll until the new access key propagates and yields an authorization decision; return
    (code, message). An unexpected success, or no decision before the deadline, raises."""
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            result = client.list_open_id_connect_providers()
        except ClientError as e:
            last_code = e.response["Error"]["Code"]
            if last_code in ("InvalidClientTokenId", "UnrecognizedClientException"):
                time.sleep(interval_s)
                continue
            return last_code, e.response["Error"].get("Message") or ""
        raise AssertionError(f"expected a zero-permission principal to be denied, but the call returned {result!r}")
    raise AssertionError(f"no authorization decision within {timeout_s}s; last observed {last_code!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
