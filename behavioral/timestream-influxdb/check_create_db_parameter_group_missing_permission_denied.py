"""create-db-parameter-group-missing-permission-denied."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "create-db-parameter-group-missing-permission-denied"
GROUP = "overly-permissive"
SERVICES = ["timestream-influxdb"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A freshly-created IAM principal with no attached policies is rejected with
    AccessDeniedException when calling CreateDbParameterGroup, while the same operation
    (positive control) succeeds using the test's own credentials."""
    iam = ctx.client("iam")
    influx = ctx.client("timestream-influxdb")
    user_name = ctx.unique_name("sim2real-denyuser-")

    iam.create_user(UserName=user_name)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))
    key = iam.create_access_key(UserName=user_name)["AccessKey"]
    access_key_id = key["AccessKeyId"]
    ctx.on_cleanup(lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=access_key_id))

    denied_client = ctx.client(
        "timestream-influxdb",
        creds={
            "aws_access_key_id": access_key_id,
            "aws_secret_access_key": key["SecretAccessKey"],
        },
    )

    denied_name = ctx.unique_name("sim2real-denied-")
    err = _wait_for_access_denied(
        lambda: denied_client.create_db_parameter_group(name=denied_name),
        timeout_s=60,
        interval_s=5,
    )
    assert err["Code"] == "AccessDeniedException", (
        f"expected AccessDeniedException, got {err['Code']!r}"
    )
    expected_message = (
        f"User: arn:aws:iam::{ctx.account}:user/{user_name} is not authorized to perform: "
        f"timestream-influxdb:CreateDbParameterGroup on resource: "
        f"arn:aws:timestream-influxdb:{ctx.region}:{ctx.account}:db-parameter-group/* because no "
        f"identity-based policy allows the timestream-influxdb:CreateDbParameterGroup action"
    )
    assert err.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err.get('Message')!r}"
    )

    # Effect absent: the denied call created nothing.
    match = _find_by_name(influx, denied_name)
    assert match is None, f"denied create must not have created a parameter group: {match!r}"

    # Positive control: the same operation succeeds with proper credentials. The
    # terminal read is independent of the create call -- GetDbParameterGroup, not the
    # create response -- so a target that echoes the request back without persisting
    # anything cannot pass by faking the create response alone.
    control_name = ctx.unique_name("sim2real-allowed-")
    created = influx.create_db_parameter_group(name=control_name)
    assert created["name"] == control_name

    fetched = influx.get_db_parameter_group(identifier=created["id"])
    assert fetched["name"] == control_name and fetched["arn"] == created["arn"], (
        f"an independent GetDbParameterGroup read must confirm the group the create call "
        f"reported: expected name={control_name!r} arn={created['arn']!r}, got {fetched!r}"
    )


def _wait_for_access_denied(fn, *, timeout_s, interval_s):
    """New IAM access keys take a few seconds to propagate; retry until the call settles on
    AccessDeniedException and return that botocore Error dict (Code and Message). An unexpected
    SUCCESS raises at once. On the deadline the last Error dict is returned."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            result = fn()
        except ClientError as err:
            last = err.response["Error"]
            if last.get("Code") == "AccessDeniedException":
                return last
        else:
            raise AssertionError(
                f"real AWS denies this call, but it SUCCEEDED and returned {result!r}"
            )
        time.sleep(interval_s)
    return last


def _find_by_name(influx, name):
    next_token = None
    for _ in range(20):
        kwargs = {"maxResults": 100}
        if next_token:
            kwargs["nextToken"] = next_token
        resp = influx.list_db_parameter_groups(**kwargs)
        for item in resp.get("items", []):
            if item["name"] == name:
                return item
        next_token = resp.get("nextToken")
        if not next_token:
            break
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
