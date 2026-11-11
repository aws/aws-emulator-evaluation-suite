"""ops-metadata-invalid-argument-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ops-metadata-invalid-argument-rejected"
GROUP = "error-semantics"
SERVICES = ["ssm"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateOpsMetadata from a role without ssm:CreateOpsMetadata is refused with AccessDenied.

    The message names the assumed role and the opsmetadata/* resource, and ListOpsMetadata shows
    nothing registered for the ResourceId. The invalid-ResourceId validation path is not reached.
    """
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    role_name = ctx.unique_name("sim2real-ssm-no-perms-opsmeta-arg-")
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
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    session_name = ctx.unique_name("sim2real-session-")
    creds = _assume_role_with_retry(sts, role_arn, session_name)

    admin_ssm = ctx.client("ssm")
    restricted_ssm = ctx.client(
        "ssm",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )

    bad_resource_id = "invalid resource id! (not ARN-safe)"

    # Positive control: an operation the harness's real credentials are actually allowed to
    # run still succeeds, proving the SSM endpoint/credential plumbing is healthy before we
    # attribute the denial below to the restricted principal rather than a broken client/endpoint.
    resp = admin_ssm.list_ops_metadata()
    assert "OpsMetadataList" in resp

    code, message = _error_retry_unrecognized(
        lambda: restricted_ssm.create_ops_metadata(ResourceId=bad_resource_id)
    )
    assert code == "AccessDeniedException", (code, message)
    assert message == (
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/{session_name} is not "
        f"authorized to perform: ssm:CreateOpsMetadata on resource: "
        f"arn:aws:ssm:{ctx.region}:{account_id}:opsmetadata/* because no identity-based "
        f"policy allows the ssm:CreateOpsMetadata action"
    ), message

    # Effect absent: the denied call must not have registered any OpsMetadata for this
    # ResourceId -- a target that returns AccessDeniedException while still performing the
    # create underneath would pass the code assertion above and only be caught here.
    listing = admin_ssm.list_ops_metadata(
        Filters=[{"Key": "ResourceId", "Values": [bad_resource_id]}]
    )
    assert listing["OpsMetadataList"] == [], listing["OpsMetadataList"]


def _assume_role_with_retry(sts, role_arn, session_name, attempts=10, delay_s=2.0):
    """IAM role-trust propagation can lag a few seconds after CreateRole; retry AssumeRole
    itself (not any check assertion) until the freshly created role is assumable."""
    last_exc = None
    for _ in range(attempts):
        try:
            resp = sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
            return resp["Credentials"]
        except ClientError as exc:
            last_exc = exc
            time.sleep(delay_s)
    raise last_exc


def _error_retry_unrecognized(fn, attempts=6, delay_s=2.0):
    """Freshly minted STS credentials can briefly be rejected as unrecognized while they
    propagate; retry the call itself (not the assertion) until credentials are live, then
    return the (code, message) of the resulting error. An accepted call raises."""
    last = None
    for _ in range(attempts):
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response["Error"]
            last = (err["Code"], err.get("Message", ""))
            if last[0] == "UnrecognizedClientException":
                time.sleep(delay_s)
                continue
            return last
        raise AssertionError(f"the call was expected to be refused but it succeeded: {result!r}")
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
