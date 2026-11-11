"""data-plane-effective-policies-reflect-attached-policies."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "data-plane-effective-policies-reflect-attached-policies"
GROUP = "server-side"
SERVICES = ["iot"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetEffectivePolicies for a principal returns exactly the union of currently attached
    policies, and the returned set grows -- and shrinks -- immediately, with no extra
    propagation delay, right after each AttachPolicy/DetachPolicy call."""
    iot = ctx.client("iot")

    policy_doc = json.dumps(
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "iot:Connect", "Resource": "*"}]}
    )
    resource_tags = [{"Key": "sim2real", "Value": CHECK}]

    # A certificate ARN is not a taggable resource type for IoT's TagResource (real AWS:
    # InvalidRequestException "Invalid resource type in ARN: cert"), so only the policies below
    # are tagged.
    cert = iot.create_keys_and_certificate(setAsActive=True)
    cert_arn = cert["certificateArn"]
    cert_id = cert["certificateId"]
    ctx.on_cleanup(lambda: _deactivate_and_delete_cert(iot, cert_id))

    policy1_name = ctx.unique_name("sim2real-iot-effpol1-")
    policy2_name = ctx.unique_name("sim2real-iot-effpol2-")
    iot.create_policy(policyName=policy1_name, policyDocument=policy_doc, tags=resource_tags)
    ctx.on_cleanup(lambda: iot.delete_policy(policyName=policy1_name))
    iot.create_policy(policyName=policy2_name, policyDocument=policy_doc, tags=resource_tags)
    ctx.on_cleanup(lambda: iot.delete_policy(policyName=policy2_name))

    iot.attach_policy(policyName=policy1_name, target=cert_arn)
    ctx.on_cleanup(lambda: _safe_detach(iot, policy1_name, cert_arn))

    got1 = iot.get_effective_policies(principal=cert_arn)
    names1 = {p["policyName"] for p in got1["effectivePolicies"]}
    assert names1 == {policy1_name}, f"expected exactly {{{policy1_name!r}}} right after attach, got {names1}"

    iot.attach_policy(policyName=policy2_name, target=cert_arn)
    ctx.on_cleanup(lambda: _safe_detach(iot, policy2_name, cert_arn))

    got2 = iot.get_effective_policies(principal=cert_arn)
    names2 = {p["policyName"] for p in got2["effectivePolicies"]}
    assert names2 == {policy1_name, policy2_name}, (
        f"expected both policies right after the second attach, got {names2}"
    )

    iot.detach_policy(policyName=policy2_name, target=cert_arn)

    got3 = iot.get_effective_policies(principal=cert_arn)
    names3 = {p["policyName"] for p in got3["effectivePolicies"]}
    assert names3 == {policy1_name}, (
        f"detaching policy2 must shrink the effective set immediately, leaving policy1 "
        f"untouched, got {names3}"
    )


def _deactivate_and_delete_cert(iot, cert_id: str) -> None:
    iot.update_certificate(certificateId=cert_id, newStatus="INACTIVE")
    iot.delete_certificate(certificateId=cert_id)


def _safe_detach(iot, policy_name: str, target: str) -> None:
    iot.detach_policy(policyName=policy_name, target=target)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
