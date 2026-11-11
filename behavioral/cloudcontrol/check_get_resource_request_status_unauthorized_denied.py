"""get-resource-request-status-unauthorized-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-resource-request-status-unauthorized-denied"
GROUP = "error-semantics"
SERVICES = ["cloudcontrol"]


@tags("axis:rejection", "cap:c4", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetResourceRequestStatus for a valid RequestToken is denied with an access-denied
    class error when called by a principal that has no IAM permission for the action --
    a distinct missing-permission boundary from the bogus-token not-found case."""
    cc = ctx.client("cloudcontrol")
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    queue_name = ctx.unique_name("sim2real-behav-queue-")
    create_resp = cc.create_resource(
        TypeName="AWS::SQS::Queue",
        DesiredState=json.dumps({"QueueName": queue_name, "Tags": [{"Key": "sim2real", "Value": CHECK}]}),
    )
    token = create_resp["ProgressEvent"]["RequestToken"]
    final = _wait_for_terminal(cc, token)
    assert final["OperationStatus"] == "SUCCESS", f"queue create must reach SUCCESS before the deny test; got {final}"
    identifier = final["Identifier"]
    sqs = ctx.client("sqs")
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=identifier))

    # A role with no attached/inline permissions at all -- an assumed session from it has
    # an implicit deny for every action, including cloudcontrol:GetResourceRequestStatus.
    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-behav-norole-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"

    denied_cc = _poll_until_assumable_cc_client(ctx, sts, role_arn)

    code, message = _poll_for_error(lambda: denied_cc.get_resource_request_status(RequestToken=token))
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code!r}"
    action = "cloudformation:GetResourceRequestStatus"
    assert message == (
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/{_SESSION_NAME} is not "
        f"authorized to perform: {action} on resource: "
        f"arn:aws:cloudformation:{ctx.region}:{account_id}:resource/* because no "
        f"identity-based policy allows the {action} action"
    ), f"the denial must name the caller, the action and the missing grant, got {message!r}"

    # Positive control: the original, permitted principal can still read the same token.
    allowed = cc.get_resource_request_status(RequestToken=token)
    assert allowed["ProgressEvent"]["RequestToken"] == token, (
        f"the original permitted principal must still read the same token; expected {token!r}, "
        f"got {allowed}"
    )


_SESSION_NAME = "sim2real-behav-denied"


def _wait_for_terminal(cc, token, timeout_s: float = 120.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cc.get_resource_request_status(RequestToken=token)["ProgressEvent"]
        if last["OperationStatus"] in ("SUCCESS", "FAILED", "CANCEL_COMPLETE"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"request {token} did not reach a terminal state in {timeout_s}s (last={last})")


def _poll_until_assumable_cc_client(ctx, sts, role_arn: str, timeout_s: float = 60.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(RoleArn=role_arn, RoleSessionName=_SESSION_NAME)["Credentials"]
            return ctx.client(
                "cloudcontrol",
                creds={
                    "aws_access_key_id": creds["AccessKeyId"],
                    "aws_secret_access_key": creds["SecretAccessKey"],
                    "aws_session_token": creds["SessionToken"],
                },
            )
        except ClientError as exc:
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"could not assume role {role_arn} in time: {last_exc}")


def _poll_for_error(fn, timeout_s: float = 45.0, interval_s: float = 3.0):
    """(code, message) of the first refusal of fn(). A call that keeps succeeding past the
    deadline raises, so a target that never denies fails loudly."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
        if time.monotonic() > deadline:
            raise AssertionError(f"expected a denial error, but the call kept succeeding: {result!r}")
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
