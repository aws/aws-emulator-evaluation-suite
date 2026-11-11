"""e2e-resource-policy-access-lifecycle."""
from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-resource-policy-access-lifecycle"
GROUP = "e2e"
SERVICES = ["rum"]


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A same-account principal with zero identity-based permissions is denied
    PutRumEvents, is granted access purely via a RUM resource policy, succeeds once
    granted, and is denied again once the policy is revoked."""
    sts = ctx.client("sts")
    iam = ctx.client("iam")
    rum = ctx.client("rum")

    account_id = sts.get_caller_identity()["Account"]

    role_name = ctx.unique_name("sim2real-rum-role-")
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
        Tags=[{"Key": "Team", "Value": "rum-fidelity"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))

    name = ctx.unique_name("sim2real-rum-e2e-")
    app_monitor_id = rum.create_app_monitor(
        Name=name, Domain="localhost", Tags={"Team": "rum-fidelity"}
    )["Id"]
    ctx.on_cleanup(lambda: _safe(lambda: rum.delete_app_monitor(Name=name)))
    app_monitor_arn = f"arn:aws:rum:{ctx.region}:{account_id}:appmonitor/{name}"

    # IAM roles take a few seconds to become assumable after creation.
    assumed_creds = _poll_for_value(
        probe=lambda: _try_assume_role(sts, role_arn),
        predicate=lambda creds: creds is not None,
        timeout_s=30.0,
        interval_s=2.0,
    )
    if assumed_creds is None:
        raise AssertionError(
            "could not assume the freshly created IAM role within 30s; "
            "cannot exercise the resource-policy-granted-principal path"
        )
    guest_rum = ctx.client(
        "rum",
        creds={
            "aws_access_key_id": assumed_creds["AccessKeyId"],
            "aws_secret_access_key": assumed_creds["SecretAccessKey"],
            "aws_session_token": assumed_creds["SessionToken"],
        },
    )

    # 1. Before any resource policy exists, the role has no permission at all -> denied.
    # Fresh session credentials can briefly be unknown to RUM (UnrecognizedClientException);
    # wait those out so the refusal graded is the authorization decision itself.
    deadline = time.monotonic() + 60.0
    while True:
        denied_code, denied_message = _client_error(
            lambda: _put_probe_event(guest_rum, app_monitor_id, name)
        )
        if denied_code != "UnrecognizedClientException" or time.monotonic() >= deadline:
            break
        time.sleep(3.0)
    assert denied_code == "AccessDeniedException", denied_code
    expected_denial = (
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/sim2real-rum-guest is not "
        f"authorized to perform: rum:PutRumEvents on resource: {app_monitor_id} because no "
        "identity-based policy allows the rum:PutRumEvents action"
    )
    assert denied_message == expected_denial, denied_message

    # 2. Grant access purely via a RUM resource-based policy naming this role.
    policy_document = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": role_arn},
                    "Action": "rum:PutRumEvents",
                    "Resource": app_monitor_arn,
                }
            ],
        }
    )
    put_resp = rum.put_resource_policy(Name=name, PolicyDocument=policy_document)
    revision_id = {"value": put_resp["PolicyRevisionId"]}
    ctx.on_cleanup(
        lambda: _safe(
            lambda: rum.delete_resource_policy(
                Name=name, PolicyRevisionId=revision_id["value"]
            )
        )
    )

    _poll_until_succeeds(
        lambda: _put_probe_event(guest_rum, app_monitor_id, name),
        "granted principal never succeeded at PutRumEvents after PutResourcePolicy",
        timeout_s=60.0,
        interval_s=3.0,
    )

    # 3. Revoke the resource policy.
    rum.delete_resource_policy(Name=name, PolicyRevisionId=revision_id["value"])
    revision_id["value"] = None

    revoked_code, revoked_message = _poll_for_error(
        lambda: _put_probe_event(guest_rum, app_monitor_id, name),
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert revoked_code == "AccessDeniedException", revoked_code
    assert revoked_message == expected_denial, revoked_message

    # 4. Restore: re-granting the identical policy must re-open access — proves the revoked
    # negative was a live enforcement effect of the policy, not some other side effect (e.g. the
    # app monitor or role having gone bad).
    restore_resp = rum.put_resource_policy(Name=name, PolicyDocument=policy_document)
    revision_id["value"] = restore_resp["PolicyRevisionId"]

    _poll_until_succeeds(
        lambda: _put_probe_event(guest_rum, app_monitor_id, name),
        "re-granting the identical resource policy did not restore PutRumEvents access",
        timeout_s=60.0,
        interval_s=3.0,
    )


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "NoSuchEntity",
            "PolicyNotFoundException",
            "ResourceNotFoundException",
        ):
            raise


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _poll_for_error(fn, *, timeout_s: float, interval_s: float):
    """Poll until fn() is refused; return the (code, message). A success keeps polling until the
    deadline, then raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return _client_error(fn)
        except AssertionError as exc:
            if time.monotonic() >= deadline:
                raise AssertionError(f"call was not refused within {timeout_s}s: {exc}") from None
        time.sleep(interval_s)


def _poll_until_succeeds(fn, failure: str, *, timeout_s: float, interval_s: float) -> None:
    """Poll until fn() succeeds; raise ``failure`` with the last refusal on timeout."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as err:
            if time.monotonic() >= deadline:
                raise AssertionError(f"{failure}: {err.response['Error']}") from None
        time.sleep(interval_s)


def _poll_for_value(probe, predicate, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        if predicate(value):
            return value
        time.sleep(interval_s)
        value = probe()
    return value


def _try_assume_role(sts, role_arn: str):
    from botocore.exceptions import ClientError

    try:
        resp = sts.assume_role(RoleArn=role_arn, RoleSessionName="sim2real-rum-guest")
        return resp["Credentials"]
    except ClientError:
        return None


def _put_probe_event(rum_client, app_monitor_id: str, app_monitor_name: str) -> None:
    rum_client.put_rum_events(
        Id=app_monitor_id,
        BatchId=str(uuid.uuid4()),
        AppMonitorDetails={
            "id": app_monitor_id,
            "name": app_monitor_name,
            "version": "1.0.0",
        },
        UserDetails={"sessionId": str(uuid.uuid4()), "userId": str(uuid.uuid4())},
        RumEvents=[
            {
                "id": str(uuid.uuid4()),
                "timestamp": datetime.now(timezone.utc),
                "type": "com.amazon.rum.custom_event",
                "details": json.dumps({"message": "sim2real-guest-probe"}),
                "metadata": json.dumps({"version": "1.0.0", "domain": "localhost"}),
            }
        ],
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
