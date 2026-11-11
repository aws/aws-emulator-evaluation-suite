"""decode-authorization-message-invalid-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "decode-authorization-message-invalid-rejected"
GROUP = 'error-semantics'
SERVICES = ['sts']

_ENCODED_MARKER = "Encoded authorization failure message:"


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A garbage EncodedMessage raises InvalidAuthorizationMessageException with the exact message,
    while a genuine encoded message from a denied RunInstances DryRun decodes to allowed=false."""

    sts = ctx.client("sts")
    iam = ctx.client("iam")

    def _error_response(fn):
        """The error response of a failing call; raises on unexpected success."""
        try:
            result = fn()
        except ClientError as exc:
            return exc.response
        raise AssertionError(f"expected the call to fail, but it succeeded: {result!r}")

    def _poll(probe, predicate, *, timeout_s, interval_s=3.0, description="condition"):
        deadline = time.monotonic() + timeout_s
        while True:
            last = probe()
            if predicate(last):
                return last
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"{description} not reached within {timeout_s}s (last observed: {last!r})")
            time.sleep(interval_s)

    def _client_with_credentials(service, creds):
        return ctx.client(service, creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        })

    def _drop_role(role_name):
        try:
            for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
                try:
                    iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "NoSuchEntity":
                        raise
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    def _try_assume(role_arn, **kw):
        try:
            return sts.assume_role(
                RoleArn=role_arn, RoleSessionName=ctx.unique_name("sim2real-behav-sess-"), **kw)
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code")

    def _wait_assumable(role_arn, **kw):
        return _poll(lambda: _try_assume(role_arn, **kw), lambda r: isinstance(r, dict),
                     timeout_s=180.0, interval_s=3.0,
                     description=f"role {role_arn} became assumable")

    def _succeeds(fn):
        """True if fn() succeeds, False on a ClientError; for polling a call expected to succeed."""
        try:
            fn()
            return True
        except ClientError:
            return False

    account = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-behav-sts-decode-")
    trust_policy = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
         "Action": "sts:AssumeRole"}]}
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy),
        MaxSessionDuration=3600, Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _drop_role(role_name))
    iam.put_role_policy(
        RoleName=role_name, PolicyName="sim2real-behav-allow-run-instances",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "ec2:RunInstances", "Resource": "*"}]}),
    )

    denying_session_policy = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": "ec2:RunInstances", "Resource": "*"},
        {"Effect": "Deny", "Action": "ec2:RunInstances", "Resource": "*"}]}
    denied_session = _wait_assumable(role_arn, Policy=json.dumps(denying_session_policy))
    denied_creds = denied_session["Credentials"]
    denied_ec2 = _client_with_credentials("ec2", denied_creds)
    denied_sts = _client_with_credentials("sts", denied_creds)

    # Freshly-issued temp creds are eventually consistent; GetCallerIdentity needs no permission,
    # so it is the safe liveness probe that proves the creds are live before the deny is tested.
    _poll(lambda: _succeeds(lambda: denied_sts.get_caller_identity()), lambda ok: ok is True,
          timeout_s=180.0, interval_s=2.0,
          description="denied session's credentials became active")

    # Resolved at runtime: a fake ImageId never reaches authorization at all (EC2 validates the
    # image id BEFORE it authorizes), so no encoded message would be produced.
    ami = ctx.client("ssm").get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]

    def _dry_run(ec2_client):
        return ec2_client.run_instances(
            ImageId=ami, InstanceType="t3.micro", MinCount=1, MaxCount=1, DryRun=True, SubnetId=ctx.network().subnet_ids[0])

    failure = _poll(
        lambda: _error_response(lambda: _dry_run(denied_ec2)),
        lambda r: isinstance(r, dict) and r.get("Error", {}).get("Code") == "UnauthorizedOperation",
        timeout_s=240.0, interval_s=3.0,
        description="the denied RunInstances DryRun became UnauthorizedOperation")
    message = failure["Error"].get("Message") or ""
    assert _ENCODED_MARKER in message, (
        "the denial carried no encoded authorization message, so there is nothing genuine to "
        f"round-trip through DecodeAuthorizationMessage as the positive control: {message!r}")
    encoded = message.split(_ENCODED_MARKER, 1)[1].strip()
    assert encoded, f"the encoded authorization message was present but empty: {message!r}"

    # Positive control: without it, a target rejecting every decode would pass the negative.
    decoded = json.loads(sts.decode_authorization_message(EncodedMessage=encoded)["DecodedMessage"])
    assert decoded.get("allowed") is False, (
        "a genuine encoded authorization failure message must decode to a real deny decision, got "
        f"{decoded!r} -- without this control, an implementation that rejects EVERY "
        "DecodeAuthorizationMessage call would pass the negative below merely by rejecting "
        "everything")

    error = _error_response(
        lambda: sts.decode_authorization_message(EncodedMessage="not-a-real-encoded-message")
    )["Error"]
    # STS echoes the base64url-decoded input as signed bytes, so the message is fixed by the input.
    assert (error.get("Code"), error.get("Message")) == (
        "InvalidAuthorizationMessageException",
        "Message is not valid: [-98, -117, 126, 107, -22, -34, 106, 95, -98, -99, -54, 29, 121, "
        "-33, -90, 122, -53, 26, -127]",
    ), error


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
