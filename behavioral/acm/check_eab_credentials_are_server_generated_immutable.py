"""eab-credentials-are-server-generated-immutable."""
from __future__ import annotations

import json
import time
import uuid
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "eab-credentials-are-server-generated-immutable"
GROUP = "server-side"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetAcmeExternalAccountBindingCredentials returns a server-generated (KeyId, MacKey) pair
    per binding: it is stable across repeated fetches, distinct across separate bindings, and
    never echoed in the Create/Describe response."""
    iam = ctx.client("iam")
    acm = ctx.client("acm")

    role_name = ctx.unique_name("sim2real-acm-eab-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "acm-acme.amazonaws.com"},
                "Action": ["sts:AssumeRole", "sts:TagSession", "sts:SetSourceIdentity"],
                "Condition": {
                    "StringLikeIfExists": {"sts:SourceIdentity": "acm-acme-*"}
                },
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    endpoint_arn = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
        Contact="NOT_REQUIRED",
        IdempotencyToken=_token("ep"),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=endpoint_arn))

    endpoint = _poll_until(
        lambda: acm.describe_acme_endpoint(AcmeEndpointArn=endpoint_arn)["AcmeEndpoint"],
        lambda ep: ep["Status"] in ("ACTIVE", "FAILED"),
        timeout_s=120,
        interval_s=3,
    )
    assert endpoint["Status"] == "ACTIVE", f"endpoint entered {endpoint['Status']}"

    eab1_arn = _create_eab(ctx, acm, endpoint_arn, role_arn, "eab1")
    eab2_arn = _create_eab(ctx, acm, endpoint_arn, role_arn, "eab2")

    create1 = acm.describe_acme_external_account_binding(AcmeExternalAccountBindingArn=eab1_arn)[
        "ExternalAccountBinding"
    ]
    assert "KeyId" not in create1 and "MacKey" not in create1, (
        f"DescribeAcmeExternalAccountBinding must never echo credential material, got keys={list(create1)}"
    )

    creds1a = acm.get_acme_external_account_binding_credentials(
        AcmeExternalAccountBindingArn=eab1_arn
    )
    creds1b = acm.get_acme_external_account_binding_credentials(
        AcmeExternalAccountBindingArn=eab1_arn
    )
    creds2 = acm.get_acme_external_account_binding_credentials(
        AcmeExternalAccountBindingArn=eab2_arn
    )

    for creds in (creds1a, creds1b, creds2):
        assert creds["KeyId"] and creds["MacKey"], f"expected non-empty server credentials, got {creds}"

    # Stable/immutable: refetching the same binding's credentials returns the identical pair.
    assert creds1a["KeyId"] == creds1b["KeyId"], "KeyId changed across repeated fetches of the same binding"
    assert creds1a["MacKey"] == creds1b["MacKey"], "MacKey changed across repeated fetches of the same binding"

    # Distinct across separate bindings: not derived from the (shared) RoleArn/endpoint alone.
    assert creds1a["KeyId"] != creds2["KeyId"], "two distinct bindings must not share a KeyId"
    assert creds1a["MacKey"] != creds2["MacKey"], "two distinct bindings must not share a MacKey"


def _token(prefix: str) -> str:
    return f"{prefix}{uuid.uuid4().hex}"[:32]


def _create_eab(ctx, acm, endpoint_arn: str, role_arn: str, tag: str) -> str:
    # IAM role trust policies can take a few seconds to propagate before other services can
    # reference the role; retry on the transient rejection window only.
    deadline = time.monotonic() + 30.0
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            resp = acm.create_acme_external_account_binding(
                AcmeEndpointArn=endpoint_arn,
                RoleArn=role_arn,
                IdempotencyToken=_token(tag),
                Tags=[{"Key": "sim2real-check", "Value": CHECK}],
            )
            arn = resp["ExternalAccountBinding"]["AcmeExternalAccountBindingArn"]
            ctx.on_cleanup(
                lambda a=arn: acm.delete_acme_external_account_binding(
                    AcmeExternalAccountBindingArn=a
                )
            )
            return arn
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("AccessDeniedException", "ValidationException"):
                last_err = exc
                time.sleep(2.0)
                continue
            raise
    raise AssertionError(f"could not create EAB after IAM propagation window: {last_err}")


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float = 60.0,
    interval_s: float = 2.0,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
