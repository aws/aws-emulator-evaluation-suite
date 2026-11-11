"""op-contract-attachVerifiedAccessTrustProvider."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-attachVerifiedAccessTrustProvider"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AttachVerifiedAccessTrustProvider wires a trust provider into an instance; DryRun rejects,
    and a nonexistent trust provider id is rejected with the specific NotFound error, leaving the
    real attachment untouched."""
    ec2 = ctx.client("ec2")

    instance_name = ctx.unique_name("sim2real-vai-")
    instance = ec2.create_verified_access_instance(
        Description=instance_name,
        TagSpecifications=[
            {"ResourceType": "verified-access-instance", "Tags": [{"Key": "Name", "Value": instance_name}]}
        ],
    )["VerifiedAccessInstance"]["VerifiedAccessInstanceId"]
    ctx.on_cleanup(lambda: _best_effort(lambda: ec2.delete_verified_access_instance(VerifiedAccessInstanceId=instance)))

    tp_name = ctx.unique_name("sim2real-vatp-")
    trust_provider = ec2.create_verified_access_trust_provider(
        TrustProviderType="user",
        UserTrustProviderType="oidc",
        PolicyReferenceName="sim2realoidc",
        OidcOptions={
            "Issuer": "https://sim2real.example.com",
            "AuthorizationEndpoint": "https://sim2real.example.com/authorize",
            "TokenEndpoint": "https://sim2real.example.com/token",
            "UserInfoEndpoint": "https://sim2real.example.com/userinfo",
            "ClientId": "sim2real-client-id",
            "ClientSecret": "sim2real-client-secret",
            "Scope": "openid",
        },
        TagSpecifications=[
            {"ResourceType": "verified-access-trust-provider", "Tags": [{"Key": "Name", "Value": tp_name}]}
        ],
    )["VerifiedAccessTrustProvider"]["VerifiedAccessTrustProviderId"]
    ctx.on_cleanup(
        lambda: _best_effort(
            lambda: ec2.delete_verified_access_trust_provider(VerifiedAccessTrustProviderId=trust_provider)
        )
    )

    # error boundary: DryRun must short-circuit with DryRunOperation before any mutation
    code, code_message = _error_code(
        lambda: ec2.attach_verified_access_trust_provider(
            VerifiedAccessInstanceId=instance, VerifiedAccessTrustProviderId=trust_provider, DryRun=True
        )
    )
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code}"
    expected_code_message = "Request would have succeeded, but DryRun flag is set."
    assert code_message == expected_code_message, f"expected message {expected_code_message!r}, got {code_message!r}"

    # success path
    resp = ec2.attach_verified_access_trust_provider(
        VerifiedAccessInstanceId=instance, VerifiedAccessTrustProviderId=trust_provider
    )
    # AttachVerifiedAccessTrustProvider's response only echoes the trust provider (there is no
    # top-level VerifiedAccessInstanceId field) -- the attachment onto the instance itself is
    # verified below via DescribeVerifiedAccessInstances.
    attached_id = resp["VerifiedAccessTrustProvider"].get("VerifiedAccessTrustProviderId")
    assert attached_id == trust_provider, f"expected attach response to echo {trust_provider}, got {attached_id}"

    def cleanup_attach():
        _best_effort(
            lambda: ec2.detach_verified_access_trust_provider(
                VerifiedAccessInstanceId=instance, VerifiedAccessTrustProviderId=trust_provider
            )
        )

    ctx.on_cleanup(cleanup_attach)

    final = _poll_until(
        lambda: ec2.describe_verified_access_instances(VerifiedAccessInstanceIds=[instance])[
            "VerifiedAccessInstances"
        ][0].get("VerifiedAccessTrustProviders", []),
        lambda providers: any(p["VerifiedAccessTrustProviderId"] == trust_provider for p in providers),
        timeout_s=30,
        interval_s=2,
    )
    final_ids = [p["VerifiedAccessTrustProviderId"] for p in final]
    assert trust_provider in final_ids, (
        f"expected {trust_provider} in instance {instance}'s VerifiedAccessTrustProviders, got {final_ids}"
    )

    # error boundary: a nonexistent trust provider id is rejected with the specific NotFound code,
    # and the real attachment made above is left untouched
    bogus_code, bogus_code_message = _error_code(
        lambda: ec2.attach_verified_access_trust_provider(
            VerifiedAccessInstanceId=instance, VerifiedAccessTrustProviderId="vatp-00000000000000000"
        )
    )
    assert bogus_code == "InvalidVerifiedAccessTrustProviderId.NotFound", (
        f"expected InvalidVerifiedAccessTrustProviderId.NotFound, got {bogus_code}"
    )
    expected_bogus_code_message = "The verified-access-trust-provider ID 'vatp-00000000000000000' does not exist"
    assert bogus_code_message == expected_bogus_code_message, f"expected message {expected_bogus_code_message!r}, got {bogus_code_message!r}"
    unaffected_ids = [
        p["VerifiedAccessTrustProviderId"]
        for p in ec2.describe_verified_access_instances(VerifiedAccessInstanceIds=[instance])[
            "VerifiedAccessInstances"
        ][0].get("VerifiedAccessTrustProviders", [])
    ]
    assert unaffected_ids == [trust_provider], (
        f"a rejected attach must not change the instance's trust providers, got {unaffected_ids}"
    )


def _best_effort(fn: Callable[[], Any]) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidVerifiedAccessInstanceId.NotFound",
            "InvalidVerifiedAccessTrustProviderId.NotFound",
        ):
            raise


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _error_code(fn: Callable[[], Any]) -> tuple[str, str | None]:
    """Call fn() and return its (code, message); a call that succeeds raises."""
    try:
        result = fn()
    except Exception as exc:
        err = getattr(exc, "response", {}).get("Error")
        if not err:
            raise
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
