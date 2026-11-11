"""get-credentials-nonexistent-binding-rejected."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-credentials-nonexistent-binding-rejected"
GROUP = "error-semantics"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetAcmeExternalAccountBindingCredentials for a nonexistent binding is refused with
    ResourceNotFoundException and the exact message and returns no credentials, while a real
    binding returns a KeyId and MacKey."""
    acm = ctx.client("acm")
    account = _account_id(ctx)
    fake_arn = (
        f"arn:aws:acm:{ctx.region}:{account}:acme-endpoint/{uuid.uuid4()}"
        f"/acme-external-account-binding/{uuid.uuid4()}"
    )

    captured = {}

    def _call():
        resp = acm.get_acme_external_account_binding_credentials(
            AcmeExternalAccountBindingArn=fake_arn
        )
        captured["resp"] = resp

    code, message = _error(_call)
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for unknown binding, got {code!r}"
    )
    expected_message = f"Could not find ACME external account binding {fake_arn}."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    assert "resp" not in captured, "credentials must not be returned for a non-existent binding"

    # Positive control: a real binding returns credentials, so a target that refuses every
    # call cannot pass the negative above.
    endpoint_arn = _create_acme_endpoint(ctx)
    role_arn = _create_eab_role(ctx)
    binding_arn = _create_binding_with_retry(ctx, endpoint_arn, role_arn)

    creds = acm.get_acme_external_account_binding_credentials(
        AcmeExternalAccountBindingArn=binding_arn
    )
    assert creds.get("KeyId"), "expected a KeyId for a real, existing binding"
    assert creds.get("MacKey"), "expected a MacKey for a real, existing binding"


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _create_acme_endpoint(ctx, contact: str = "NOT_REQUIRED") -> str:
    acm = ctx.client("acm")
    resp = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
        Contact=contact,
    )
    arn = resp["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: _delete_endpoint(ctx, arn))
    status = _wait_for_endpoint_terminal(ctx, arn)
    if status != "ACTIVE":
        raise AssertionError(f"AcmeEndpoint {arn} settled in status {status}, expected ACTIVE")
    return arn


def _wait_for_endpoint_terminal(
    ctx, arn: str, timeout_s: float = 120.0, interval_s: float = 3.0
) -> str:
    acm = ctx.client("acm")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]["Status"]
        if last in ("ACTIVE", "FAILED"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"AcmeEndpoint {arn} never left a non-terminal status; last={last}")


def _delete_endpoint(ctx, arn: str) -> None:
    """Teardown: delete the endpoint, retrying the documented ConflictException while it is still
    settling; an endpoint that is already gone is accepted, anything else raises."""
    from botocore.exceptions import ClientError

    acm = ctx.client("acm")
    deadline = time.monotonic() + min(120.0, ctx.time_left() or 120.0)
    while True:
        try:
            acm.delete_acme_endpoint(AcmeEndpointArn=arn)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException" or time.monotonic() >= deadline:
                raise
        time.sleep(2.0)


def _create_eab_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-acme-eab-role-")
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
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    ctx.on_cleanup(lambda: _delete_role_ignore_errors(ctx, role_name))
    return resp["Role"]["Arn"]


def _delete_role_ignore_errors(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_binding_with_retry(ctx, endpoint_arn: str, role_arn: str, timeout_s: float = 60.0) -> str:
    acm = ctx.client("acm")
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            resp = acm.create_acme_external_account_binding(
                AcmeEndpointArn=endpoint_arn, RoleArn=role_arn
            )
            binding_arn = resp["ExternalAccountBinding"]["AcmeExternalAccountBindingArn"]
            ctx.on_cleanup(lambda: _delete_binding_ignore_errors(ctx, binding_arn))
            return binding_arn
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDeniedException", "ValidationException"):
                last_err = e
                time.sleep(3.0)
                continue
            raise
    raise AssertionError(f"CreateAcmeExternalAccountBinding never succeeded: {last_err}")


def _delete_binding_ignore_errors(ctx, binding_arn: str) -> None:
    acm = ctx.client("acm")
    acm.delete_acme_external_account_binding(AcmeExternalAccountBindingArn=binding_arn)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
