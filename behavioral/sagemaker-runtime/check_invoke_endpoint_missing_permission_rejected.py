"""invoke-endpoint-missing-permission-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "invoke-endpoint-missing-permission-rejected"
GROUP = "overly-permissive"
SERVICES = ["sagemaker-runtime"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """InvokeEndpoint from a principal with no permissions fails with AccessDeniedException, while
    a permitted caller on the same nonexistent endpoint gets ValidationError "not found", so
    authorization is evaluated before resource lookup."""
    smr = ctx.client("sagemaker-runtime")
    bogus_endpoint = ctx.unique_name("sim2real-smrt-never-created-")

    baseline_code, baseline_msg = _error(lambda: smr.invoke_endpoint(EndpointName=bogus_endpoint, Body=b"x"))
    assert baseline_code == "ValidationError", f"expected ValidationError, got {baseline_code}: {baseline_msg}"
    expected_baseline = f"Endpoint {bogus_endpoint} of account {ctx.account} not found."
    assert baseline_msg == expected_baseline, f"expected {expected_baseline!r}, got {baseline_msg!r}"

    role_name, role_arn = _create_no_permissions_role(ctx)
    session_name = ctx.unique_name("sim2real-smrt-noperm-session-")
    no_perms_smr = _client_from_role(ctx, role_arn, session_name)
    denied_code, denied_msg = _error(
        lambda: no_perms_smr.invoke_endpoint(EndpointName=bogus_endpoint, Body=b"denied-caller")
    )
    assert denied_code == "AccessDeniedException", f"expected AccessDeniedException, got {denied_code}: {denied_msg}"
    expected_denied = (
        f"User: arn:aws:sts::{ctx.account}:assumed-role/{role_name}/{session_name} is not authorized "
        f"to perform: sagemaker:InvokeEndpoint on resource: "
        f"arn:aws:sagemaker:{ctx.region}:{ctx.account}:endpoint/{bogus_endpoint} "
        "because no identity-based policy allows the sagemaker:InvokeEndpoint action"
    )
    assert denied_msg == expected_denied, f"expected {expected_denied!r}, got {denied_msg!r}"


def _create_no_permissions_role(ctx) -> tuple[str, str]:
    """Create an IAM role with a trust policy only (no attached policies, so it has zero
    effective permissions) and return its name and ARN."""
    iam = ctx.client("iam")
    account_id = ctx.account

    role_name = ctx.unique_name("sim2real-smrt-noperm-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    # no policies are ever attached to this role: it carries zero permissions by design.
    return role_name, iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _client_from_role(ctx, role_arn: str, session_name: str):
    """A sagemaker-runtime client signing as the freshly-assumed role against the same target."""
    sts = ctx.client("sts")
    creds = _assume_role_with_retry(sts, role_arn, session_name)
    return ctx.client(
        "sagemaker-runtime",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


def _assume_role_with_retry(sts, role_arn: str, session_name: str, timeout_s: float = 40.0, interval_s: float = 3.0):
    """Assume the role, retrying AccessDenied within a deadline while the new role propagates."""
    deadline = time.monotonic() + timeout_s
    last_exc: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)["Credentials"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in ("AccessDenied", "AccessDeniedException"):
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"AssumeRole still denied after {timeout_s}s: {last_exc}")


def _delete_role(iam, role_name: str) -> None:
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


def _error(fn):
    """The rejection's (code, message). Raises if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection but the call SUCCEEDED: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
