"""access-denied-without-permission-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "access-denied-without-permission-rejected"
GROUP = "overly-permissive"
SERVICES = ["bcm-recommended-actions"]


def _error_response(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response
    return None


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An IAM principal with zero attached permissions gets AccessDeniedException; a fully-permissioned caller does not."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    admin_client = ctx.client("bcm-recommended-actions")

    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-bcmra-noperm-")
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real-behav", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    # No permission policy is attached: the role has no allow statement for anything, so
    # every Billing/Cost Management action (including ListRecommendedActions) is denied
    # by IAM's default-deny.
    from botocore.exceptions import ClientError

    creds = None
    last_err = None
    for _ in range(10):
        try:
            resp = sts.assume_role(RoleArn=role_arn, RoleSessionName="sim2real-bcmra-probe")
            creds = resp["Credentials"]
            break
        except ClientError as err:  # role trust policy propagation can lag briefly
            last_err = err
            time.sleep(2)
    assert creds is not None, f"could not assume freshly-created role: {last_err}"

    # ctx.client's `creds` override re-signs with the assumed role's temporary credentials while
    # keeping the target's own endpoint/region/TLS wiring — real AWS on the real-AWS arm, the
    # shared emulator endpoint on the emulator arm. A hand-rolled boto3.client() with no
    # endpoint_url would default to the real public endpoint even when the check is being graded
    # against an emulator, silently sending the "restricted" call somewhere the emulator never sees.
    restricted = ctx.client(
        "bcm-recommended-actions",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )

    # A freshly-assumed role's credentials can briefly read as UnrecognizedClientException before
    # they propagate; retry past that, and only that, until the authorization verdict arrives.
    error = None
    for _ in range(15):
        error = _error_response(lambda: restricted.list_recommended_actions())
        if error is not None and error["Error"]["Code"] != "UnrecognizedClientException":
            break
        time.sleep(2)

    assert error is not None, "expected the permission-less role to be denied"
    assert error["Error"]["Code"] == "AccessDeniedException", (
        f"expected AccessDeniedException, got {error['Error']['Code']}: {error['Error'].get('Message')}"
    )
    partition = role_arn.split(":")[1]
    expected_message = (
        f"User: arn:{partition}:sts::{account_id}:assumed-role/{role_name}/sim2real-bcmra-probe "
        "is not authorized to perform: bcm-recommended-actions:ListRecommendedActions because no "
        "identity-based policy allows the bcm-recommended-actions:ListRecommendedActions action"
    )
    assert error["Error"].get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error['Error'].get('Message')!r}"
    )

    # Positive control: the fully-permissioned caller can still list actions.
    control = admin_client.list_recommended_actions()
    assert isinstance(control["recommendedActions"], list), (
        f"expected the admin caller's list_recommended_actions to succeed with a list, got "
        f"{type(control.get('recommendedActions'))!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
