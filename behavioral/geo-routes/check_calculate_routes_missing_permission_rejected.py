"""calculate-routes-missing-permission-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "calculate-routes-missing-permission-rejected"
GROUP = "overly-permissive"
SERVICES = ["geo-routes"]

_ORIGIN = [-122.3421, 47.6097]
_DESTINATION = [-122.3493, 47.6205]
_SESSION_NAME = "sim2real-georoutes-noperm"


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"real AWS denies this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A role with no policies gets AccessDeniedException and its exact message from CalculateRoutes while the
    check's own credentials route, and the same role routes once geo-routes:CalculateRoutes is granted.
    """
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    role_name = ctx.unique_name("sim2real-georoutes-noperm-")
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

    creds = None
    deadline = time.monotonic() + 30.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(
                RoleArn=role_arn, RoleSessionName=_SESSION_NAME
            )["Credentials"]
            break
        except ClientError as err:
            last_err = err
            time.sleep(2.0)
    if creds is None:
        raise AssertionError(f"could not assume freshly-created role in time: {last_err}")

    privileged = ctx.client("geo-routes")
    # Sign as the assumed role through ctx.client's creds override, so the client keeps the endpoint of the
    # target under test.
    restricted_client = ctx.client(
        "geo-routes",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )

    error = _client_error(
        lambda: restricted_client.calculate_routes(
            Origin=_ORIGIN, Destination=_DESTINATION, TravelMode="Car"
        )
    )
    assert error["Code"] == "AccessDeniedException", f"expected AccessDeniedException, got {error!r}"
    expected_message = (
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/{_SESSION_NAME} "
        f"is not authorized to perform: geo-routes:CalculateRoutes on resource: "
        f"arn:aws:geo-routes:{ctx.region}::provider/default because no identity-based "
        f"policy allows the geo-routes:CalculateRoutes action"
    )
    assert error["Message"] == expected_message, (
        f"unexpected message: {error['Message']!r}"
    )

    # Positive control: the check's own credentials can make the identical call.
    resp = privileged.calculate_routes(Origin=_ORIGIN, Destination=_DESTINATION, TravelMode="Car")
    assert len(resp["Routes"]) >= 1

    # Restore: grant the same role the missing permission; the identical call through the same restricted
    # client then succeeds, so the denial tracked the role's policy.
    allow_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "geo-routes:CalculateRoutes", "Resource": "*"}
        ],
    }
    policy_name = "allow-calculate-routes"
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(allow_policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    restored = None
    deadline = time.monotonic() + 120.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            restored = restricted_client.calculate_routes(
                Origin=_ORIGIN, Destination=_DESTINATION, TravelMode="Car"
            )
            break
        except ClientError as err:
            last_err = err
            time.sleep(5.0)
    if restored is None:
        raise AssertionError(
            f"restricted client still denied after granting the policy: {last_err}"
        )
    assert len(restored["Routes"]) >= 1


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
