"""concurrent-create-external-account-binding-duplicate-name-conflict."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-create-external-account-binding-duplicate-name-conflict"
GROUP = "concurrency"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent CreateAcmeExternalAccountBinding calls sharing an IdempotencyToken return
    the same ARN, and the endpoint ends up with exactly one binding, never two."""

    acm = ctx.client("acm")
    iam = ctx.client("iam")

    role_arn = _create_eab_role(ctx, iam)
    endpoint_arn = _create_acme_endpoint(ctx, acm)
    _wait_for_endpoint_active(acm, endpoint_arn)
    _wait_role_usable(acm, endpoint_arn, role_arn)

    # The binding has no user-supplied name; its collision key is the IdempotencyToken.
    token = ctx.unique_name("sim2real-eab-token-")

    def _create() -> str:
        return acm.create_acme_external_account_binding(
            AcmeEndpointArn=endpoint_arn,
            RoleArn=role_arn,
            IdempotencyToken=token,
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )["ExternalAccountBinding"]["AcmeExternalAccountBindingArn"]

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_create) for _ in range(2)]
        arns = [f.result() for f in futures]

    ctx.on_cleanup(
        lambda: acm.delete_acme_external_account_binding(AcmeExternalAccountBindingArn=arns[0])
    )

    assert arns[0] == arns[1], (
        f"two concurrent creates sharing an IdempotencyToken produced different bindings: {arns}"
    )

    listed = acm.list_acme_external_account_bindings(AcmeEndpointArn=endpoint_arn).get(
        "ExternalAccountBindings", []
    )
    assert len(listed) == 1, (
        f"expected exactly one external account binding on the endpoint after the concurrent "
        f"idempotent creates, found {len(listed)}"
    )
    assert listed[0]["AcmeExternalAccountBindingArn"] == arns[0], (
        "the single listed binding does not match the ARN both concurrent callers received"
    )


def _create_acme_endpoint(ctx, acm, contact: str = "NOT_REQUIRED") -> str:
    resp = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        Contact=contact,
        CertificateAuthority={"PublicCertificateAuthority": {}},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    arn = resp["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=arn))
    return arn


def _wait_for_endpoint_active(acm, arn: str, timeout_s: float = 180.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        endpoint = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]
        status = endpoint["Status"]
        if status == "ACTIVE":
            return
        if status == "FAILED":
            raise AssertionError(f"ACME endpoint {arn} failed: {endpoint.get('FailureReason')}")
        time.sleep(3)
    raise AssertionError(f"ACME endpoint {arn} never became ACTIVE within {timeout_s}s")


def _create_eab_role(ctx, iam) -> str:
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
    name = ctx.unique_name("sim2real-acme-eab-role-")
    resp = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _wait_role_usable(acm, endpoint_arn: str, role_arn: str, timeout_s: float = 90.0) -> None:
    """IAM roles are eventually consistent; probe with a throwaway EAB create/delete
    until ACM can successfully assume the freshly created role."""
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        probe_token = f"{role_arn.rsplit('/', 1)[-1]}-probe-{time.monotonic_ns()}"
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
