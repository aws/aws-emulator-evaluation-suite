"""attach-policy-nonexistent-target-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "attach-policy-nonexistent-target-rejected"
GROUP = "server-side"
SERVICES = ["iot"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AttachPolicy against a syntactically valid but nonexistent certificate ARN is
    rejected with ResourceNotFoundException, leaves no attachment behind, and a
    positive control attaching the same policy to a real certificate still succeeds."""
    iot = ctx.client("iot")
    sts = ctx.client("sts")

    policy_name = ctx.unique_name("sim2real-iot-negattach-")
    iot.create_policy(
        policyName=policy_name,
        policyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "iot:Connect", "Resource": "*"}],
            }
        ),
        tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iot.delete_policy(policyName=policy_name))

    account_id = sts.get_caller_identity()["Account"]
    bogus_cert_arn = f"arn:aws:iot:{ctx.region}:{account_id}:cert/{'0' * 64}"

    err = _error(lambda: iot.attach_policy(policyName=policy_name, target=bogus_cert_arn))
    assert err == ("ResourceNotFoundException", "The certificate given in the principal does not exist."), (
        f"expected ResourceNotFoundException attaching to a nonexistent target, got {err!r}"
    )

    # The effect is absent: nothing was attached to the bogus target.
    targets = iot.list_targets_for_policy(policyName=policy_name)["targets"]
    assert bogus_cert_arn not in targets, f"bogus target leaked into policy targets: {targets!r}"
    assert targets == [], f"expected no targets attached after the rejected attach, got {targets!r}"

    # Positive control: attaching the very same policy to a real certificate succeeds.
    cert = iot.create_keys_and_certificate(setAsActive=True)
    cert_arn = cert["certificateArn"]
    cert_id = cert["certificateId"]

    def _cleanup_cert():
        iot.detach_policy(policyName=policy_name, target=cert_arn)
        iot.update_certificate(certificateId=cert_id, newStatus="INACTIVE")
        iot.delete_certificate(certificateId=cert_id)

    ctx.on_cleanup(_cleanup_cert)

    iot.attach_policy(policyName=policy_name, target=cert_arn)
    targets_after = iot.list_targets_for_policy(policyName=policy_name)["targets"]
    assert cert_arn in targets_after, (
        f"positive control: expected {cert_arn!r} among targets after attach, got {targets_after!r}"
    )


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises; a success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
