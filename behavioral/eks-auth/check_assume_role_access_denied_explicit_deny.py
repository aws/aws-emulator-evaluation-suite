"""assume-role-access-denied-explicit-deny."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "assume-role-access-denied-explicit-deny"
GROUP = "overly-permissive"
SERVICES = ["eks-auth"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A caller explicitly denied eks-auth:AssumeRoleForPodIdentity gets AccessDeniedException even
    for a bogus clusterName/token, so authorization runs before request validation; the same
    request from an unrestricted caller fails with a different code."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    role_name = ctx.unique_name("sim2real-eksa-deny-")

    try:
        account_id = sts.get_caller_identity()["Account"]
        trust = {
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
            AssumeRolePolicyDocument=json.dumps(trust),
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )["Role"]["Arn"]
        ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

        deny_policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Deny", "Action": "eks-auth:AssumeRoleForPodIdentity", "Resource": "*"}],
        }
        iam.put_role_policy(RoleName=role_name, PolicyName="deny-eks-auth", PolicyDocument=json.dumps(deny_policy))
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="deny-eks-auth"))
    except ClientError as exc:
        raise AssertionError(
            "IAM/STS scaffolding (create_role/get_caller_identity) is not reachable in this "
            f"environment ({exc.response.get('Error', {}).get('Code', 'Unknown')!r}); exercising an "
            "explicit-deny IAM boundary for eks-auth requires cross-service IAM/STS access this "
            "harness does not provide here"
        ) from exc

    bogus_cluster = ctx.unique_name("sim2real-nonexistent-")
    bogus_token = "not-a-jwt-at-all"

    def _assume_restricted():
        creds = _retry_assume_role(sts, role_arn, ctx.unique_name("sess-"))
        restricted_eks_auth = ctx.client(
            "eks-auth",
            creds={
                "aws_access_key_id": creds["AccessKeyId"],
                "aws_secret_access_key": creds["SecretAccessKey"],
                "aws_session_token": creds["SessionToken"],
            },
        )
        return _error_code(
            lambda: restricted_eks_auth.assume_role_for_pod_identity(clusterName=bogus_cluster, token=bogus_token)
        )

    # New IAM policies take seconds to become effective; _poll_until raises on timeout.
    _poll_until(_assume_restricted, expect="AccessDeniedException", attempts=12, delay=5)

    # Positive control: without the deny, the same bogus request fails validation instead,
    # so the denial above is specific to this caller.
    unrestricted_eks_auth = ctx.client("eks-auth")
    code2 = _error_code(
        lambda: unrestricted_eks_auth.assume_role_for_pod_identity(clusterName=bogus_cluster, token=bogus_token)
    )
    assert code2 != "AccessDeniedException", f"GOT={code2!r}"


def _error_code(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    raise AssertionError(
        "assume_role_for_pod_identity was expected to be refused (bogus clusterName/token) but it "
        "SUCCEEDED -- an over-permissive target would launder this as a plain code mismatch if this "
        "returned a falsy sentinel instead of raising"
    )


def _retry_assume_role(sts, role_arn, session_name, attempts=12, delay=5):
    last_exc = None
    for _ in range(attempts):
        try:
            return sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)["Credentials"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] in ("AccessDenied", "AccessDeniedException"):
                last_exc = exc
                time.sleep(delay)
                continue
            raise
    raise last_exc


def _poll_until(fn, expect, attempts=12, delay=5):
    last = None
    for _ in range(attempts):
        last = fn()
        if last == expect:
            return last
        time.sleep(delay)
    raise AssertionError(f"expected {expect!r} within {attempts * delay}s of polling, last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

