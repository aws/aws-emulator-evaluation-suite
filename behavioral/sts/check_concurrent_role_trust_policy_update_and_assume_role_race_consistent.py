"""concurrent-role-trust-policy-update-and-assume-role-race-consistent."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-role-trust-policy-update-and-assume-role-race-consistent"
GROUP = "concurrency"
SERVICES = ["sts"]


@tags("axis:happy-path", "cap:c7", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssumeRole calls racing a trust-policy update each end in a clean success (a usable session)
    or AccessDenied, GetRole then returns the new principal, and a fresh role with the new
    document admits only its named user and denies the caller."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    caller = sts.get_caller_identity()
    account_id = caller["Account"]
    role_name = ctx.unique_name("sim2real-behav-trustrace-")
    other_user_name = ctx.unique_name("sim2real-behav-trustrace-other-")

    # A user that is NOT the caller: swapping the trust Principal from the account root to this
    # user gives a condition-free signal of which policy version a call observed.
    tags_kv = [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}]
    other_user_arn = iam.create_user(UserName=other_user_name, Tags=tags_kv)["User"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_user(UserName=other_user_name))
    other_key = iam.create_access_key(UserName=other_user_name)["AccessKey"]
    ctx.on_cleanup(lambda: iam.delete_access_key(UserName=other_user_name, AccessKeyId=other_key["AccessKeyId"]))

    open_trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "sts:AssumeRole",
        }],
    }
    gated_trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": other_user_arn},
            "Action": "sts:AssumeRole",
        }],
    }

    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(open_trust), Tags=tags_kv
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    # A brand-new IAM principal is briefly rejected as an invalid trust-policy principal
    # (MalformedPolicyDocument: "Invalid principal in policy").
    def _retry_until_principal_propagates(fn, timeout_s=30):
        deadline = time.monotonic() + timeout_s
        while True:
            try:
                return fn()
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "MalformedPolicyDocument" or time.monotonic() >= deadline:
                    raise
                time.sleep(2)

    def _try_assume(client=None):
        client = client or sts
        kwargs = {"RoleArn": role_arn, "RoleSessionName": ctx.unique_name("sess-")[:64]}
        try:
            resp = client.assume_role(**kwargs)
            return {"success": True, "error_code": None, "creds": resp["Credentials"]}
        except ClientError as exc:
            return {
                "success": False,
                "error_code": exc.response["Error"]["Code"],
                "error_message": exc.response["Error"].get("Message"),
                "creds": None,
            }

    # New roles have a short IAM propagation lag before they can actually be assumed.
    deadline = time.monotonic() + 30
    baseline = None
    while time.monotonic() < deadline:
        baseline = _try_assume()
        if baseline["success"]:
            break
        time.sleep(2)
    assert baseline is not None and baseline["success"], (
        f"role never became assumable under the open trust policy: {baseline}"
    )

    with ThreadPoolExecutor(max_workers=13) as pool:
        update_future = pool.submit(
            _retry_until_principal_propagates,
            lambda: iam.update_assume_role_policy(RoleName=role_name, PolicyDocument=json.dumps(gated_trust)),
        )
        race_futures = [pool.submit(_try_assume) for _ in range(12)]
        update_future.result()
        race_results = [f.result() for f in race_futures]

    caller_arn = caller["Arn"]
    for result in race_results:
        assert result["error_code"] in (None, "AccessDenied"), (
            f"unexpected outcome during the trust-policy race: {result['error_code']}"
        )
        if result["error_code"] == "AccessDenied":
            assert result["error_message"] == (
                f"User: {caller_arn} is not authorized to perform: sts:AssumeRole on resource: {role_arn}"
            ), result

    # A mid-race success must be a usable session; fresh STS credentials can take an instant
    # to become usable.
    successes = [r for r in race_results if r["success"]]
    if successes:
        sample_creds = successes[0]["creds"]
        sample_client = _client_with_creds(ctx, sts, sample_creds)
        verify_deadline = time.monotonic() + 15
        identity = None
        last_verify_exc = None
        while time.monotonic() < verify_deadline:
            try:
                identity = sample_client.get_caller_identity()
                break
            except ClientError as exc:
                last_verify_exc = exc
                time.sleep(2)
        assert identity is not None, f"race-issued session credentials never became usable: {last_verify_exc}"
        assert role_name in identity["Arn"], identity["Arn"]


    # GetRole can lag slightly behind UpdateAssumeRolePolicy.
    repr_deadline = time.monotonic() + 30
    stored_principal = None
    stored_policy = None
    while time.monotonic() < repr_deadline:
        stored_policy = iam.get_role(RoleName=role_name)["Role"]["AssumeRolePolicyDocument"]
        stored_principal = stored_policy["Statement"][0]["Principal"]["AWS"]
        if stored_principal == other_user_arn:
            break
        time.sleep(2)
    assert stored_principal == other_user_arn, (
        f"IAM control plane did not durably store the new trust policy: {stored_policy}"
    )


    # Check what gated_trust grants on a FRESH role: creation-time propagation is fast, while
    # an update to an existing role can take longer than a bounded check can wait.
    control_role_name = ctx.unique_name("sim2real-behav-trustrace-ctrl-")
    control_role_arn = _retry_until_principal_propagates(
        lambda: iam.create_role(
            RoleName=control_role_name, AssumeRolePolicyDocument=json.dumps(gated_trust), Tags=tags_kv
        )
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=control_role_name))

    def _try_assume_control(client=None):
        client = client or sts
        try:
            client.assume_role(RoleArn=control_role_arn, RoleSessionName=ctx.unique_name("sess-")[:64])
            return {"success": True, "error_code": None}
        except ClientError as exc:
            return {
                "success": False,
                "error_code": exc.response["Error"]["Code"],
                "error_message": exc.response["Error"].get("Message"),
            }

    other_client = ctx.client(
        "sts",
        creds={
            "aws_access_key_id": other_key["AccessKeyId"],
            "aws_secret_access_key": other_key["SecretAccessKey"],
        },
    )

    # Positive control: the trusted principal can assume the gated role.
    control_deadline = time.monotonic() + 30
    allowed = None
    while time.monotonic() < control_deadline:
        allowed = _try_assume_control(client=other_client)
        if allowed["success"]:
            break
        time.sleep(2)
    assert allowed is not None and allowed["success"] is True, (
        f"expected the gated policy's own trusted principal to be able to assume the role: {allowed}"
    )

    # This role never had a broader grant, so the caller's denial needs no poll.
    denied = _try_assume_control()
    assert denied["success"] is False, f"ambient caller unexpectedly assumed the gated-only role: {denied}"
    assert denied["error_code"] == "AccessDenied", denied
    assert denied["error_message"] == (
        f"User: {caller_arn} is not authorized to perform: sts:AssumeRole on resource: {control_role_arn}"
    ), denied


def _client_with_creds(ctx, base_client, creds):
    return ctx.client(
        "sts",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

