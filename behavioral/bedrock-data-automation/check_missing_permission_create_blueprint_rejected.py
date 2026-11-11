"""missing-permission-create-blueprint-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "missing-permission-create-blueprint-rejected"
GROUP = "overly-permissive"
SERVICES = ["bedrock-data-automation"]

_SCHEMA = json.dumps(
    {
        "class": "Denied",
        "description": "missing-permission schema",
        "properties": {"x": {"type": "string", "inferenceType": "explicit", "instruction": "x"}},
    }
)


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A caller assuming an IAM role with NO attached permissions gets AccessDeniedException on
    CreateBlueprint; the default (permitted) caller in the same file still succeeds (positive
    control), proving the rejection is permission-specific, not a blanket API outage."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    role_name = ctx.unique_name("sim2real-bda-noperm-role")
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

    session_name = "sim2real-bda-noperm-session"
    denied_client = _assume_role_client(ctx, sts, role_arn, session_name)

    denied_name = ctx.unique_name("sim2real-bda-bp-denied")
    code, message = _poll_for_error_code(
        lambda: denied_client.create_blueprint(
            blueprintName=denied_name, type="DOCUMENT", schema=_SCHEMA
        ),
        timeout_s=30.0,
        interval_s=3.0,
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code!r}"
    expected_message = (
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/{session_name} is not authorized "
        f"to perform: bedrock:CreateBlueprint on resource: "
        f"arn:aws:bedrock:{ctx.region}:{account_id}:blueprint/* because no identity-based policy "
        f"allows the bedrock:CreateBlueprint action"
    )
    assert message == expected_message, f"unexpected message: {message!r}"

    # Effect absent: the denied CreateBlueprint must not have taken effect, via an
    # independent ListBlueprints read (a different operation than the one that was denied).
    bda = ctx.client("bedrock-data-automation")
    existing_names = {b["blueprintName"] for b in _list_all_blueprints(bda)}
    assert denied_name not in existing_names, (
        f"denied create must not have created a Blueprint named {denied_name!r}"
    )

    # Positive control: the default (permitted) credentials can still create a Blueprint.
    name = ctx.unique_name("sim2real-bda-bp-allowed")
    arn = bda.create_blueprint(blueprintName=name, type="DOCUMENT", schema=_SCHEMA)["blueprint"]["blueprintArn"]
    ctx.on_cleanup(lambda: bda.delete_blueprint(blueprintArn=arn))
    got_name = bda.get_blueprint(blueprintArn=arn)["blueprint"]["blueprintName"]
    assert got_name == name, f"expected blueprintName {name!r}, got {got_name!r}"


def _assume_role_client(ctx, sts, role_arn: str, session_name: str):
    last_err = None
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)["Credentials"]
            break
        except Exception as err:  # noqa: BLE001 - role trust may not have propagated yet
            last_err = err
            time.sleep(2.0)
    else:
        raise AssertionError(f"could not assume role in time: {last_err}")

    # ctx.client's `creds` override re-signs with the assumed-role identity while keeping
    # THIS run's endpoint/TLS wiring (real AWS vs. emulator) -- a bare boto3.client(...) here
    # would have no endpoint_url and send the asserted request straight to real AWS regardless
    # of which target this run is actually exercising.
    return ctx.client(
        "bedrock-data-automation",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


def _list_all_blueprints(bda) -> list[dict]:
    blueprints: list[dict] = []
    next_token = None
    while True:
        kwargs = {"nextToken": next_token} if next_token else {}
        resp = bda.list_blueprints(**kwargs)
        blueprints.extend(resp.get("blueprints", []))
        next_token = resp.get("nextToken")
        if not next_token:
            break
    return blueprints


def _poll_for_error_code(fn, *, timeout_s=30.0, interval_s=3.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last = (None, None)
    while time.monotonic() < deadline:
        try:
            fn()
            raise AssertionError("call unexpectedly succeeded with a no-permission role")
        except ClientError as err:
            last = (err.response["Error"]["Code"], err.response["Error"].get("Message"))
            if last[0] == "AccessDeniedException":
                return last
            time.sleep(interval_s)
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
