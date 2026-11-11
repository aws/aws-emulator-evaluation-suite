"""op-contract-put-account-configuration."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags

CHECK = "op-contract-put-account-configuration"
GROUP = "error-semantics"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:acm-account-configuration")
def run(ctx) -> None:
    """PutAccountConfiguration changes DaysBeforeExpiry as GetAccountConfiguration reflects; a role
    with no policies is denied with AccessDeniedException and leaves the value unchanged."""
    acm = ctx.client("acm")

    original = acm.get_account_configuration()["ExpiryEvents"]["DaysBeforeExpiry"]
    new_value = 30 if original != 30 else 21

    resp = acm.put_account_configuration(
        ExpiryEvents={"DaysBeforeExpiry": new_value},
        IdempotencyToken=uuid.uuid4().hex[:24],
    )
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200

    def _restore():
        acm.put_account_configuration(
            ExpiryEvents={"DaysBeforeExpiry": original},
            IdempotencyToken=uuid.uuid4().hex[:24],
        )

    ctx.on_cleanup(_restore)

    reflected = acm.get_account_configuration()["ExpiryEvents"]["DaysBeforeExpiry"]
    assert reflected == new_value, f"expected {new_value}, got {reflected}"

    # IAM's implicit deny rejects the call before ACM applies the write.
    denied_acm, denied_role_name = _acm_client_for_permissionless_role(ctx)
    code, message = _error(
        lambda: denied_acm.put_account_configuration(
            ExpiryEvents={"DaysBeforeExpiry": 15}, IdempotencyToken=uuid.uuid4().hex[:24]
        )
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code}"
    expected = (
        f"User: arn:aws:sts::{ctx.account}:assumed-role/{denied_role_name}/sim2real-acm-noperm "
        "is not authorized to perform: acm:PutAccountConfiguration because no identity-based "
        "policy allows the acm:PutAccountConfiguration action"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    unchanged = acm.get_account_configuration()["ExpiryEvents"]["DaysBeforeExpiry"]
    assert unchanged == new_value, f"denied PutAccountConfiguration must not mutate account config, got {unchanged}"


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError("expected the call to be rejected, but it succeeded")


def _acm_client_for_permissionless_role(ctx):
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    role_name = ctx.unique_name("sim2real-acm-noperm-")
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
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "env", "Value": "sim2real"}, {"Key": "purpose", "Value": "behavioral-test"}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"

    deadline = time.monotonic() + 30.0
    last_exc = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(
                RoleArn=role_arn, RoleSessionName="sim2real-acm-noperm"
            )["Credentials"]
            break
        except Exception as exc:  # role not yet assumable (propagation delay)
            last_exc = exc
            time.sleep(2.0)
    else:
        raise AssertionError(f"role never became assumable: {last_exc}")

    client = ctx.client(
        "acm",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )
    return client, role_name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
