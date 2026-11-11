"""iam-role-trust-sqs-amazonaws-com-positive."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "iam-role-trust-sqs-amazonaws-com-positive"
GROUP = "iam-trust"
SERVICES = ["glue", "sqs"]


@tags("axis:happy-path", "cap:c7", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A role whose trust policy includes sqs.amazonaws.com is accepted, persisted verbatim,
    and is genuinely assumable (proving IAM did not silently reject/normalize the service
    principal statement)."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    role_name = ctx.unique_name("sim2real-sqs-trust-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "sqs.amazonaws.com"},
                "Action": "sts:AssumeRole",
            },
            {
                # Lets this test process itself assume the role so we can prove the trust
                # document is genuinely honored by STS, not merely echoed back by CreateRole.
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            },
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    # 1) The persisted trust document still contains the sqs.amazonaws.com statement.
    described = iam.get_role(RoleName=role_name)["Role"]["AssumeRolePolicyDocument"]
    services = _principal_services(described)
    assert "sqs.amazonaws.com" in services, f"sqs.amazonaws.com missing from persisted trust doc: {described}"

    # 2) The role is genuinely assumable (STS honors the trust statement mechanically).
    creds = _assume_role_with_retry(ctx, role_arn, timeout_s=90, interval_s=5)
    assumed_sts = _sts_client_from_creds(ctx, creds)
    identity = assumed_sts.get_caller_identity()
    partition = role_arn.split(":")[1]
    expected_arn = f"arn:{partition}:sts::{account_id}:assumed-role/{role_name}/sim2real-trust-check"
    assert identity["Arn"] == expected_arn, f"assumed identity does not reflect the role: {identity}"
    assert identity["Account"] == account_id, (
        f"assumed identity account {identity['Account']!r} does not match caller account {account_id!r}"
    )


def _principal_services(policy_doc: dict[str, Any]) -> set[str]:
    out: set[str] = set()
    for stmt in policy_doc.get("Statement", []):
        principal = stmt.get("Principal", {})
        if isinstance(principal, dict):
            svc = principal.get("Service")
            if isinstance(svc, str):
                out.add(svc)
            elif isinstance(svc, list):
                out.update(svc)
    return out


def _assume_role_with_retry(ctx, role_arn: str, timeout_s: float = 90, interval_s: float = 5) -> dict[str, Any]:
    sts = ctx.client("sts")
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            resp = sts.assume_role(RoleArn=role_arn, RoleSessionName="sim2real-trust-check")
            return resp["Credentials"]
        except Exception as exc:  # freshly created role: IAM propagation delay
            last_err = exc
            time.sleep(interval_s)
    raise AssertionError(f"assume_role kept failing: {last_err}")


def _sts_client_from_creds(ctx, creds: dict[str, Any]):
    return ctx.client(
        "sts",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
