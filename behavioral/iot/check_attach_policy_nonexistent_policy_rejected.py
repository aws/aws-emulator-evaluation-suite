"""attach-policy-nonexistent-policy-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "attach-policy-nonexistent-policy-rejected"
GROUP = "server-side"
SERVICES = ["iot"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AttachPolicy for a policyName that does not exist is rejected, leaves the target
    untouched, and a real policy can still be attached to the same target afterward."""
    iot = ctx.client("iot")

    bogus_policy_name = ctx.unique_name("sim2real-iot-missing-policy-")

    cert = iot.create_keys_and_certificate(setAsActive=True)
    cert_arn = cert["certificateArn"]
    cert_id = cert["certificateId"]

    def _cleanup_cert():
        iot.update_certificate(certificateId=cert_id, newStatus="INACTIVE")
        iot.delete_certificate(certificateId=cert_id, forceDelete=True)

    ctx.on_cleanup(_cleanup_cert)

    err = _error(lambda: iot.attach_policy(policyName=bogus_policy_name, target=cert_arn))
    assert err == ("ResourceNotFoundException", "Policy not found"), (
        f"expected ResourceNotFoundException naming the missing policy, got {err!r}"
    )

    # Effect absence: nothing got attached to the certificate.
    attached = iot.list_attached_policies(target=cert_arn)["policies"]
    assert attached == [], f"expected no attached policies, got {attached}"

    # Positive control: a real policy attaches to the same target without issue.
    real_policy_name = ctx.unique_name("sim2real-iot-real-policy-")
    policy_document = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "iot:Connect", "Resource": "*"}],
        }
    )
    iot.create_policy(
        policyName=real_policy_name,
        policyDocument=policy_document,
        tags=[{"Key": "sim2real", "Value": bogus_policy_name}],
    )
    ctx.on_cleanup(lambda: iot.delete_policy(policyName=real_policy_name))

    iot.attach_policy(policyName=real_policy_name, target=cert_arn)
    ctx.on_cleanup(lambda: iot.detach_policy(policyName=real_policy_name, target=cert_arn))

    attached_after = iot.list_attached_policies(target=cert_arn)["policies"]
    got_names = [p["policyName"] for p in attached_after]
    assert got_names == [real_policy_name], f"expected only {real_policy_name!r} attached, got {got_names}"


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected AttachPolicy to be rejected, but it SUCCEEDED: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
