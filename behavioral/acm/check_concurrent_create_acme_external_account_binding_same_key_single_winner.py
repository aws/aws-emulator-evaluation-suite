"""concurrent-create-acme-external-account-binding-same-key-single-winner."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-create-acme-external-account-binding-same-key-single-winner"
GROUP = "concurrency"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx: Any) -> None:
    """Two CreateAcmeExternalAccountBinding calls racing with one IdempotencyToken but different
    RoleArns persist exactly one binding carrying the winner's role, and the loser gets
    ConflictException: never two bindings for one token, never zero."""
    acm = ctx.client("acm")
    endpoint_arn = _create_endpoint(ctx)
    _wait_for_endpoint_active(ctx, endpoint_arn)
    role_a = _create_eab_role(ctx, "a")
    role_b = _create_eab_role(ctx, "b")
    _wait_role_usable(ctx, endpoint_arn, role_a)
    _wait_role_usable(ctx, endpoint_arn, role_b)

    token = ctx.unique_name("sim2real-acm-eab-token-")

    def creator(role_arn: str) -> tuple[str, str, str | None]:
        try:
            resp = acm.create_acme_external_account_binding(
                AcmeEndpointArn=endpoint_arn,
                RoleArn=role_arn,
                IdempotencyToken=token,
            )
            return (role_arn, "ok", resp["ExternalAccountBinding"]["AcmeExternalAccountBindingArn"])
        except ClientError as exc:
            return (role_arn, exc.response["Error"]["Code"], exc.response["Error"].get("Message"))

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = [
            f.result()
            for f in [pool.submit(creator, role_a), pool.submit(creator, role_b)]
        ]

    oks = [(role_arn, arn) for role_arn, status, arn in outcomes if status == "ok"]
    losers = [status for _, status, _ in outcomes if status != "ok"]
    loser_messages = [message for _, status, message in outcomes if status != "ok"]

    assert len(oks) == 1, f"expected exactly one winning binding, got outcomes={outcomes}"
    assert len(losers) == 1, f"expected exactly one rejected racer, got outcomes={outcomes}"
    assert losers[0] == "ConflictException", f"loser got unexpected error code: {losers[0]}"
    assert loser_messages[0] == "Idempotency token was already used with different request parameters", loser_messages[0]

    winning_role_arn, winner_arn = oks[0]
    ctx.on_cleanup(
        lambda: acm.delete_acme_external_account_binding(AcmeExternalAccountBindingArn=winner_arn)
    )

    described = acm.describe_acme_external_account_binding(
        AcmeExternalAccountBindingArn=winner_arn
    )["ExternalAccountBinding"]
    assert described["RoleArn"] == winning_role_arn, (
        f"binding {winner_arn} should carry the role of the racer that actually won "
        f"({winning_role_arn}), got {described['RoleArn']}"
    )

    bindings = acm.list_acme_external_account_bindings(AcmeEndpointArn=endpoint_arn)[
        "ExternalAccountBindings"
    ]
    matching = [b for b in bindings if b["AcmeExternalAccountBindingArn"] == winner_arn]
    assert len(matching) == 1, f"expected exactly one persisted binding, found: {bindings}"
    assert len(bindings) == 1, f"expected the endpoint to have exactly one binding total, found: {bindings}"


def _create_endpoint(ctx: Any) -> str:
    acm = ctx.client("acm")
    resp = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
        Contact="NOT_REQUIRED",
        Tags=[{"Key": "sim2real-check", "Value": ctx.unique_name("acme-eab-winner-")}],
    )
    arn = resp["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=arn))
    return arn


def _wait_for_endpoint_active(ctx: Any, arn: str, timeout_s: float = 180.0) -> dict:
    acm = ctx.client("acm")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        endpoint = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]
        status = endpoint["Status"]
        if status == "ACTIVE":
            return endpoint
        if status == "FAILED":
            raise AssertionError(f"ACME endpoint {arn} failed: {endpoint.get('FailureReason')}")
        time.sleep(3)
    raise AssertionError(f"ACME endpoint {arn} never became ACTIVE within {timeout_s}s")


_EAB_TRUST_POLICY = {
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

_EAB_PERMISSIONS_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["acm:RequestCertificate", "acm:RevokeCertificate"],
            "Resource": "*",
        }
    ],
}


def _create_eab_role(ctx: Any, suffix: str = "") -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name(f"sim2real-acm-eab-role-{suffix}-" if suffix else "sim2real-acm-eab-role-")
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_EAB_TRUST_POLICY),
        Tags=[{"Key": "sim2real-check", "Value": role_name}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="acm-acme-cert-ops",
        PolicyDocument=json.dumps(_EAB_PERMISSIONS_POLICY),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="acm-acme-cert-ops"))
    return role_arn


def _wait_role_usable(ctx: Any, endpoint_arn: str, role_arn: str, timeout_s: float = 90.0) -> None:
    """IAM roles are eventually consistent; probe with a throwaway EAB create/delete
    until ACM can successfully assume the freshly created role."""
    acm = ctx.client("acm")
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        probe_token = ctx.unique_name("sim2real-acm-eab-probe-")
        try:
            resp = acm.create_acme_external_account_binding(
                AcmeEndpointArn=endpoint_arn, RoleArn=role_arn, IdempotencyToken=probe_token
            )
            probe_arn = resp["ExternalAccountBinding"]["AcmeExternalAccountBindingArn"]
            acm.delete_acme_external_account_binding(AcmeExternalAccountBindingArn=probe_arn)
            return
        except ClientError as exc:
            last_code = exc.response["Error"]["Code"]
            if last_code != "AccessDeniedException":
                raise
            time.sleep(3)
    raise AssertionError(f"role {role_arn} never became usable for EAB creation: {last_code}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
