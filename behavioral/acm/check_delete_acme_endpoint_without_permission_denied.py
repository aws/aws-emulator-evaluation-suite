"""delete-acme-endpoint-without-permission-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-acme-endpoint-without-permission-denied"
GROUP = "overly-permissive"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c4", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteAcmeEndpoint with zero-permission credentials fails with AccessDeniedException; the
    endpoint stays ACTIVE, and the caller's own credentials can still delete it."""
    acm = ctx.client("acm")
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    endpoint_arn = _create_active_endpoint(ctx, acm)

    role_name, role_arn = _create_no_permission_role(ctx, iam, sts)
    low_priv_creds = _assume_role_with_retry(sts, role_arn)
    low_priv_acm = ctx.client(
        "acm",
        creds={
            "aws_access_key_id": low_priv_creds["AccessKeyId"],
            "aws_secret_access_key": low_priv_creds["SecretAccessKey"],
            "aws_session_token": low_priv_creds["SessionToken"],
        },
    )

    code, message = _error_code(lambda: low_priv_acm.delete_acme_endpoint(AcmeEndpointArn=endpoint_arn))
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code} ({message!r})"
    account_id = sts.get_caller_identity()["Account"]
    expected_message = (
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/{_SESSION_NAME} is not authorized "
        f"to perform: acm:DeleteAcmeEndpoint on resource: {endpoint_arn} because no identity-based "
        "policy allows the acm:DeleteAcmeEndpoint action"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: the endpoint is untouched and still ACTIVE
    described = acm.describe_acme_endpoint(AcmeEndpointArn=endpoint_arn)["AcmeEndpoint"]
    assert described["Status"] == "ACTIVE", f"expected endpoint to remain ACTIVE, got {described['Status']}"

    # positive control: the caller's own (permitted) credentials can delete it
    acm.delete_acme_endpoint(AcmeEndpointArn=endpoint_arn)
    _poll_until_endpoint_gone(acm, endpoint_arn)


_SESSION_NAME = "sim2real-acme-noperm-session"


def _error_code(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _ignore(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_active_endpoint(ctx, acm, contact: str | None = None) -> str:
    kwargs = {
        "AuthorizationBehavior": "PRE_APPROVED",
        "CertificateAuthority": {"PublicCertificateAuthority": {}},
    }
    if contact:
        kwargs["Contact"] = contact
    arn = acm.create_acme_endpoint(**kwargs)["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: _ignore(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=arn)))
    status = _wait_for_endpoint_status(acm, arn, {"ACTIVE", "FAILED"})
    if status != "ACTIVE":
        raise AssertionError(f"endpoint entered {status} instead of ACTIVE")
    return arn


def _wait_for_endpoint_status(
    acm, arn: str, target_statuses: set, timeout_s: float = 90.0, interval_s: float = 3.0
) -> str:
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        last_status = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]["Status"]
        if last_status in target_statuses:
            return last_status
        time.sleep(interval_s)
    raise AssertionError(f"endpoint {arn} never reached {target_statuses}, last status={last_status}")


def _poll_until_endpoint_gone(acm, arn: str, timeout_s: float = 60.0, interval_s: float = 2.0) -> None:
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            acm.describe_acme_endpoint(AcmeEndpointArn=arn)
        except ClientError as exc:
            last_code = exc.response["Error"]["Code"]
            if last_code == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"endpoint {arn} still describable after deletion (last_code={last_code})")


def _create_no_permission_role(ctx, iam, sts) -> tuple[str, str]:
    account_id = sts.get_caller_identity()["Account"]
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_name = ctx.unique_name("sim2real-acme-noperm-")
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _ignore(lambda: iam.delete_role(RoleName=role_name)))
    # No policies are attached: the role carries zero permissions by design. IAM eventual
    # consistency is absorbed by _assume_role_with_retry retrying on AccessDenied.
    return role_name, role_arn


def _assume_role_with_retry(sts, role_arn: str, timeout_s: float = 40.0, interval_s: float = 3.0) -> dict:
    deadline = time.monotonic() + timeout_s
    last_exc: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return sts.assume_role(RoleArn=role_arn, RoleSessionName=_SESSION_NAME)["Credentials"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("AccessDenied", "AccessDeniedException"):
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"AssumeRole still denied after {timeout_s}s: {last_exc}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
