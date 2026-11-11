"""test-authorization-policy-evaluation."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "test-authorization-policy-evaluation"
GROUP = 'policy-lifecycle'
SERVICES = ['iot']

def _eventually(fn, predicate, timeout_s: int = 60, interval_s: float = 2.0):
    """Poll ``fn`` until ``predicate`` holds, tolerating transient exceptions.

    Real AWS IoT propagates registry/job writes asynchronously, so the first few
    reads can raise ResourceNotFoundException before settling.
    """

    deadline = time.time() + timeout_s
    last_exc = None
    last_val = None
    while time.time() < deadline:
        try:
            last_val = fn()
            if predicate(last_val):
                return last_val
            last_exc = None
        except Exception as exc:  # noqa: BLE001 - transient propagation
            last_exc = exc
        time.sleep(interval_s)
    if last_exc is not None:
        raise AssertionError(f"condition never became true; last error: {last_exc!r}")
    raise AssertionError(f"condition never became true; last value: {last_val!r}")

def _delete_certificate(iot, cert_id):
    """Teardown: detach policies/things, deactivate, then force-delete; a missing certificate is clean."""
    try:
        cert_arn = iot.describe_certificate(certificateId=cert_id)[
            "certificateDescription"
        ]["certificateArn"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    try:
        for p in iot.list_attached_policies(target=cert_arn).get("policies", []):
            iot.detach_policy(policyName=p["policyName"], target=cert_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        for t in iot.list_principal_things(principal=cert_arn).get("things", []):
            try:
                iot.detach_thing_principal(thingName=t, principal=cert_arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        iot.update_certificate(certificateId=cert_id, newStatus="INACTIVE")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        iot.delete_certificate(certificateId=cert_id, forceDelete=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise

def _delete_policy(iot, name):
    """Best-effort teardown: delete non-default versions, detach targets, then delete a policy."""
    try:
        for v in iot.list_policy_versions(policyName=name).get("policyVersions", []):
            if not v.get("isDefaultVersion"):
                try:
                    iot.delete_policy_version(policyName=name, policyVersionId=v["versionId"])
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                        raise
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        for t in iot.list_targets_for_policy(policyName=name).get("targets", []):
            iot.detach_policy(policyName=name, target=t)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        iot.delete_policy(policyName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise

@tags("axis:happy-path", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TestAuthorization implements real IoT policy evaluation: no policy => IMPLICIT_DENY,
    an Allow => ALLOWED, and an explicit Deny overrides the Allow => EXPLICIT_DENY."""
    iot = ctx.client("iot")
    account = ctx.client("sts").get_caller_identity()["Account"]

    created = iot.create_keys_and_certificate(setAsActive=True)
    cert_id = created["certificateId"]
    cert_arn = created["certificateArn"]
    ctx.on_cleanup(lambda _n=cert_id: _delete_certificate(iot, _n))

    topic = f"arn:aws:iot:{ctx.region}:{account}:topic/sim2real/probe"
    auth_infos = [{"actionType": "PUBLISH", "resources": [topic]}]

    def decision():
        return iot.test_authorization(principal=cert_arn, authInfos=auth_infos)[
            "authResults"
        ][0]["authDecision"]

    assert decision() == "IMPLICIT_DENY", (
        f"a principal with no policy must be IMPLICIT_DENY, got {decision()}"
    )

    allow_policy = ctx.unique_name("sim2real-behav-policy-allow-")
    iot.create_policy(
        policyName=allow_policy,
        policyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "iot:Publish", "Resource": topic}
                ],
            }
        ),
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda _n=allow_policy: _delete_policy(iot, _n))
    iot.attach_policy(policyName=allow_policy, target=cert_arn)

    _eventually(decision, lambda d: d == "ALLOWED", timeout_s=60)

    # An explicit Deny must beat the Allow -- deny-wins is the core of IAM-style eval.
    deny_policy = ctx.unique_name("sim2real-behav-policy-deny-")
    iot.create_policy(
        policyName=deny_policy,
        policyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Deny", "Action": "iot:Publish", "Resource": topic}
                ],
            }
        ),
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda _n=deny_policy: _delete_policy(iot, _n))
    iot.attach_policy(policyName=deny_policy, target=cert_arn)

    final = _eventually(decision, lambda d: d == "EXPLICIT_DENY", timeout_s=60)
    assert final == "EXPLICIT_DENY", f"explicit Deny must override Allow, got {final}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
