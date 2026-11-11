"""access-denied-rejected."""
from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "access-denied-rejected"
GROUP = "overly-permissive"
SERVICES = ["signer"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetRevocationStatus succeeds for the unrestricted caller, while an identity with an explicit Deny on
    signer:GetRevocationStatus is rejected with AccessDeniedException and the exact message.
    """
    signer = ctx.client("signer")
    common = dict(
        platformId="Notation-OCI-SHA384-ECDSA",
        jobArn=f"arn:aws:signer:{ctx.region}:111122223333:/signing-jobs/{'a' * 20}",
        profileVersionArn=f"arn:aws:signer:{ctx.region}:111122223333:/signing-profiles/n/{'a' * 10}",
        certificateHashes=["a" * 192],
        signatureTimestamp=datetime.now(timezone.utc),
    )

    # Positive control: the default test identity can call the operation.
    resp = signer.get_revocation_status(**common)
    revoked_entities = resp.get("revokedEntities")
    assert isinstance(revoked_entities, list), (
        f"the default (unrestricted) identity's GetRevocationStatus must succeed and return a "
        f"list for revokedEntities; got {revoked_entities!r}"
    )

    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    role_name = ctx.unique_name("sim2real-signer-deny-")
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
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    deny_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Deny", "Action": "signer:GetRevocationStatus", "Resource": "*"}
        ],
    }
    policy_name = "deny-get-revocation-status"
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(deny_policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    session_name = f"sim2real-{uuid.uuid4().hex[:8]}"
    denied_signer = _assume_role_client(ctx, sts, role_arn, session_name, "signer")

    # Break exactly one thing: call with an identity explicitly denied this action, polling for the
    # denial because IAM changes take seconds to propagate. Removing the Deny can leave the same
    # session denied for minutes, so the unrestricted control above stands in for a restore leg.
    code, message = _poll_until(
        lambda: _client_error(lambda: denied_signer.get_revocation_status(**common)),
        lambda err: err[0] == "AccessDeniedException",
        timeout_s=90.0,
        interval_s=3.0,
        description="the deny policy on signer:GetRevocationStatus takes effect for the assumed role",
    )
    assert code == "AccessDeniedException", (
        f"an identity with an explicit Deny on signer:GetRevocationStatus must be refused with "
        f"AccessDeniedException; got {code!r}"
    )
    expected = (
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/{session_name} is not "
        f"authorized to perform: signer:GetRevocationStatus on resource: "
        f"arn:aws:signer:{ctx.region}:111122223333:/signing-profiles/n with an explicit deny "
        f"in an identity-based policy"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _client_error(fn):
    """The captured AWS error code and message, or a sentinel code that cannot be mistaken for one
    on success."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    return "UNEXPECTED_SUCCESS", None


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


def _assume_role_client(ctx: Any, sts_client: Any, role_arn: str, session_name: str, service: str):
    deadline = time.monotonic() + 30.0
    last_exc = None
    while time.monotonic() < deadline:
        try:
            creds = sts_client.assume_role(
                RoleArn=role_arn, RoleSessionName=session_name
            )["Credentials"]
            return ctx.client(
                service,
                creds={
                    "aws_access_key_id": creds["AccessKeyId"],
                    "aws_secret_access_key": creds["SecretAccessKey"],
                    "aws_session_token": creds["SessionToken"],
                },
            )
        except ClientError as exc:
            last_exc = exc
            time.sleep(2.0)
    raise AssertionError(f"could not assume role {role_arn}: {last_exc}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
