"""get-effective-policies-reflects-attached-policies."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-effective-policies-reflects-attached-policies"
GROUP = "server-side"
SERVICES = ["iot"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetEffectivePolicies mirrors AttachPolicy/DetachPolicy state for a certificate principal."""
    iot = ctx.client("iot")

    policy_name = ctx.unique_name("sim2real-iot-policy-")
    policy_document = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "iot:Connect", "Resource": "*"}],
        }
    )
    iot.create_policy(
        policyName=policy_name,
        policyDocument=policy_document,
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iot.delete_policy(policyName=policy_name))

    cert = iot.create_keys_and_certificate(setAsActive=True)
    cert_arn = cert["certificateArn"]
    cert_id = cert["certificateId"]

    def _cleanup_cert():
        iot.update_certificate(certificateId=cert_id, newStatus="INACTIVE")
        iot.delete_certificate(certificateId=cert_id, forceDelete=True)

    ctx.on_cleanup(_cleanup_cert)

    # Before attaching: the certificate has no effective policies.
    before = iot.get_effective_policies(principal=cert_arn)["effectivePolicies"]
    before_names = [p["policyName"] for p in before]
    assert policy_name not in before_names, (
        f"a freshly created certificate must have no effective policy named {policy_name!r} "
        f"before any attach, got {before_names}"
    )

    def _safe_detach():
        iot.detach_policy(policyName=policy_name, target=cert_arn)

    iot.attach_policy(policyName=policy_name, target=cert_arn)
    ctx.on_cleanup(_safe_detach)

    attached = _poll_until(
        lambda: iot.get_effective_policies(principal=cert_arn)["effectivePolicies"],
        lambda policies: policy_name in [p["policyName"] for p in policies],
        timeout_s=30.0,
    )
    names = [p["policyName"] for p in attached]
    assert names == [policy_name], f"expected exactly [{policy_name}], got {names}"

    iot.detach_policy(policyName=policy_name, target=cert_arn)

    after = _poll_until(
        lambda: iot.get_effective_policies(principal=cert_arn)["effectivePolicies"],
        lambda policies: policy_name not in [p["policyName"] for p in policies],
        timeout_s=30.0,
    )
    assert after == [], f"expected no effective policies after detach, got {after}"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
