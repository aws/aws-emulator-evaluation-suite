"""op-contract-detach-verified-access-trust-provider."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-detach-verified-access-trust-provider"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DetachVerifiedAccessTrustProvider removes the trust provider from the Verified Access instance's
    list, and an unknown trust provider ID fails with InvalidVerifiedAccessTrustProviderId.NotFound
    and its exact message."""

    ec2 = ctx.client("ec2")
    if not hasattr(ec2, "create_verified_access_trust_provider"):
        raise AssertionError("Verified Access API not supported by installed botocore")

    instance_id = ec2.create_verified_access_instance(
        TagSpecifications=_tag_spec(ctx, "verified-access-instance", ctx.unique_name("sim2real-vai-"))
    )["VerifiedAccessInstance"]["VerifiedAccessInstanceId"]
    ctx.on_cleanup(lambda: ec2.delete_verified_access_instance(VerifiedAccessInstanceId=instance_id))

    tp_id = ec2.create_verified_access_trust_provider(
        TrustProviderType="user",
        UserTrustProviderType="oidc",
        PolicyReferenceName="sim2realtp",
        OidcOptions={
            "Issuer": "https://sim2real.example.com",
            "AuthorizationEndpoint": "https://sim2real.example.com/authorize",
            "TokenEndpoint": "https://sim2real.example.com/token",
            "UserInfoEndpoint": "https://sim2real.example.com/userinfo",
            "ClientId": "sim2real-client",
            "ClientSecret": "sim2real-secret",
            "Scope": "openid",
        },
        TagSpecifications=_tag_spec(
            ctx, "verified-access-trust-provider", ctx.unique_name("sim2real-vatp-")
        ),
    )["VerifiedAccessTrustProvider"]["VerifiedAccessTrustProviderId"]
    ctx.on_cleanup(
        lambda: ec2.delete_verified_access_trust_provider(VerifiedAccessTrustProviderId=tp_id)
    )

    ec2.attach_verified_access_trust_provider(
        VerifiedAccessInstanceId=instance_id, VerifiedAccessTrustProviderId=tp_id
    )
    attached = _poll_until(
        lambda: ec2.describe_verified_access_instances(VerifiedAccessInstanceIds=[instance_id])[
            "VerifiedAccessInstances"
        ][0].get("VerifiedAccessTrustProviders", []),
        lambda providers: any(p["VerifiedAccessTrustProviderId"] == tp_id for p in providers),
        timeout_s=30.0,
    )
    assert any(p["VerifiedAccessTrustProviderId"] == tp_id for p in attached), (
        f"expected {tp_id} attached to {instance_id}, describe returned {attached!r}"
    )

    ec2.detach_verified_access_trust_provider(
        VerifiedAccessInstanceId=instance_id, VerifiedAccessTrustProviderId=tp_id
    )
    detached = _poll_until(
        lambda: ec2.describe_verified_access_instances(VerifiedAccessInstanceIds=[instance_id])[
            "VerifiedAccessInstances"
        ][0].get("VerifiedAccessTrustProviders", []),
        lambda providers: not any(p["VerifiedAccessTrustProviderId"] == tp_id for p in providers),
        timeout_s=30.0,
    )
    assert not any(p["VerifiedAccessTrustProviderId"] == tp_id for p in detached), (
        f"expected {tp_id} detached from {instance_id}, describe still returned {detached!r}"
    )

    code, message = _client_error(
        lambda: ec2.detach_verified_access_trust_provider(
            VerifiedAccessInstanceId=instance_id,
            VerifiedAccessTrustProviderId="vatp-00000000000000000",
        )
    )
    assert code == "InvalidVerifiedAccessTrustProviderId.NotFound", (
        f"expected InvalidVerifiedAccessTrustProviderId.NotFound detaching a bogus trust "
        f"provider id, got {code!r}"
    )
    # Only the stable end of the not-found message is pinned.
    assert message.endswith(" vatp-00000000000000000 does not exist"), (
        f"expected the not-found message for vatp-00000000000000000, got {message!r}"
    )


def _tag_spec(ctx, resource_type: str, name: str):
    return [
        {
            "ResourceType": resource_type,
            "Tags": [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "true"}],
        }
    ]


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _client_error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
