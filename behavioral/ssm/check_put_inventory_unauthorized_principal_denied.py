"""put-inventory-unauthorized-principal-denied."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-inventory-unauthorized-principal-denied"
GROUP = "error-semantics"
SERVICES = ["ssm"]


def _client_error(fn):
    """The captured AWS error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control", "resource:account-singleton:ssm-custom-inventory-schemas")
def run(ctx) -> None:
    """PutInventory with a fabricated InstanceId fails with InvalidInstanceId (empty message) for
    the caller, but with AccessDeniedException and the exact denial for a role without
    ssm:PutInventory; the caller's other SSM reads still answer."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    role_name = ctx.unique_name("sim2real-ssm-no-perms-inv-")
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

    bogus_instance_id = "i-" + "0" * 17
    capture_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    items = [
        {
            "TypeName": "Custom:SimParitySchema",
            "SchemaVersion": "1.0",
            "CaptureTime": capture_time,
            "Content": [{"Key": "Value"}],
        }
    ]

    # Positive control on the identical request: the already-authorized admin credentials hit
    # InstanceId validation, never authorization, proving the request itself is well-formed and
    # reaches business logic for a caller who is allowed to call it.
    admin_code, admin_message = _client_error(
        lambda: admin_ssm.put_inventory(InstanceId=bogus_instance_id, Items=items)
    )
    assert admin_code == "InvalidInstanceId", (
        f"an authorized caller's PutInventory against a fabricated InstanceId must fail "
        f"InstanceId validation, not authorization; got {admin_code!r}"
    )
    assert admin_message == "", f"unexpected message {admin_message!r}"

    # The restricted principal, same request, no ssm:PutInventory permission: denied before
    # any InstanceId/node logic runs.
    restricted_code, restricted_message = _client_error(
        lambda: restricted_ssm.put_inventory(InstanceId=bogus_instance_id, Items=items)
    )
    assert restricted_code == "AccessDeniedException", (
        f"a role with no ssm:PutInventory permission must be denied with "
        f"AccessDeniedException; got {restricted_code!r}"
    )
    assert restricted_message == (
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/{session_name} is not "
        f"authorized to perform: ssm:PutInventory on resource: "
        f"arn:aws:ec2:{ctx.region}:{account_id}:instance/{bogus_instance_id} because no "
        f"identity-based policy allows the ssm:PutInventory action"
    ), (
        f"unexpected message {restricted_message!r}"
    )

    # Terminal, independent read at the destination: a different operation the caller's
    # credentials are actually allowed to run still succeeds, proving the SSM
    # endpoint/credential plumbing is healthy throughout and every denial above is specific to
    # the restricted principal, not a broken client/endpoint.
    resp = admin_ssm.describe_instance_information(MaxResults=5)
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"admin DescribeInstanceInformation must succeed; got "
        f"{resp['ResponseMetadata']['HTTPStatusCode']}"
    )


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
