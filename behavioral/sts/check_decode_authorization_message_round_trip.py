"""decode-authorization-message-round-trip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "decode-authorization-message-round-trip"
GROUP = 'error-semantics'
SERVICES = ['sts']


@tags("axis:happy-path", "cap:c7", "concern:negative-classes",
      "concern:representation", "plane:control")
def run(ctx) -> None:
    """An encoded authorization failure message from a denied EC2 CreateVolume (DryRun) decodes via
    DecodeAuthorizationMessage to allowed=false for this role session and the CreateVolume action."""

    sts = ctx.client("sts")

    def _make_client_for(service):
        return ctx.client(service)

    def _client_with_credentials(service, creds):
        return ctx.client(
            service,
            creds={
                "aws_access_key_id": creds["AccessKeyId"],
                "aws_secret_access_key": creds["SecretAccessKey"],
                "aws_session_token": creds.get("SessionToken"),
            },
        )

    def _creds_accepted(probe):
        # InvalidClientTokenId is the documented answer for not-yet-propagated temp creds.
        try:
            probe.get_caller_identity()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidClientTokenId":
                raise
            return False
        return True

    def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
        deadline = time.monotonic() + timeout_s
        last = None
        while time.monotonic() < deadline:
            last = probe()
            if predicate(last):
                return last
            time.sleep(interval_s)
        raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

    def _wait_creds_active(creds, service="sts"):
        # Freshly-issued temp creds are eventually consistent; every target gets the same
        # deadline, and one that activates them at once ends the poll at once.
        probe = _client_with_credentials(service, creds)
        timeout_s, interval_s = 60, 2.0
        _poll_until(
            lambda: _creds_accepted(probe),
            lambda ok: ok is True, timeout_s=timeout_s, interval_s=interval_s,
            description="temporary credentials became active",
        )

    def _account_id():
        return sts.get_caller_identity()["Account"]

    def _tags_kv():
        return [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}]

    def _default_trust_policy():
        account_id = _account_id()
        return {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                    "Action": ["sts:AssumeRole", "sts:TagSession", "sts:SetSourceIdentity"],
                }
            ],
        }

    def _wait_role_assumable(role_arn, assume_kwargs=None, timeout_s=120, interval_s=3.0):
        kwargs = dict(assume_kwargs or {})

        def probe():
            try:
                sts.assume_role(
                    RoleArn=role_arn, RoleSessionName=ctx.unique_name("sim2real-behav-probe-"), **kwargs
                )
                return True
            except Exception:  # noqa: BLE001
                return False

        _poll_until(
            probe, lambda v: v is True, timeout_s=timeout_s, interval_s=interval_s,
            description=f"role {role_arn} became assumable",
        )

    def _create_assumable_role(trust_policy=None, max_session_duration=3600, inline_policy=None,
                               assume_kwargs=None):
        role_name = ctx.unique_name("sim2real-behav-sts-role-")
        policy = trust_policy if trust_policy is not None else _default_trust_policy()
        resp = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(policy),
            MaxSessionDuration=max_session_duration,
            Tags=_tags_kv(),
        )

        def _drop_role(role_name=role_name):
            # NoSuchEntity means the role or policy is already gone; anything else is a real failure.
            try:
                for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
                    try:
                        iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
                    except iam.exceptions.NoSuchEntityException:
                        pass
                iam.delete_role(RoleName=role_name)
            except iam.exceptions.NoSuchEntityException:
                pass

        ctx.on_cleanup(_drop_role)
        role_arn = resp["Role"]["Arn"]
        if inline_policy is not None:
            iam.put_role_policy(
                RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(inline_policy)
            )
        _wait_role_assumable(role_arn, assume_kwargs=assume_kwargs)
        return role_name, role_arn

    def _provoke_encoded_authorization_message(creds):
        # A denied resource-level EC2 mutation carries an STS-encoded failure message (a denied
        # DescribeInstances does not). DryRun is evaluated after authorization, so nothing is created.
        ec2 = _client_with_credentials("ec2", creds)
        az = _make_client_for("ec2").describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"][0]["ZoneName"]

        def probe():
            try:
                ec2.create_volume(DryRun=True, AvailabilityZone=az, Size=1)
                return None
            except Exception as exc:  # noqa: BLE001
                response = getattr(exc, "response", None)
                if not response:
                    return None
                return response.get("Error", {}).get("Message") or response.get("Message")

        marker = "Encoded authorization failure message:"
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            msg = probe()
            if msg and marker in msg:
                return msg.split(marker, 1)[1].strip()
            time.sleep(2.0)
        raise AssertionError(
            "no encoded authorization failure message could be provoked in this "
            f"account/region; DecodeAuthorizationMessage round-trip is not exercisable. last={msg!r}"
        )

    iam = _make_client_for("iam")

    inline = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["sts:GetCallerIdentity"], "Resource": "*"}],
    }
    role_name, role_arn = _create_assumable_role(inline_policy=inline)
    session_name = ctx.unique_name("sim2real-behav-sess-")
    resp = sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
    _wait_creds_active(resp["Credentials"])

    encoded = _provoke_encoded_authorization_message(resp["Credentials"])
    decoded_resp = sts.decode_authorization_message(EncodedMessage=encoded)
    decoded = json.loads(decoded_resp["DecodedMessage"])

    assert decoded.get("allowed") is False, decoded
    context = decoded.get("context", {})
    principal = json.dumps(context.get("principal", {}))
    assert role_name in principal or session_name in principal, decoded
    assert context.get("action", "").endswith("CreateVolume"), context.get("action")

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
