"""principal-policy-legacy-attach-detach."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "principal-policy-legacy-attach-detach"
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

def _policy_doc(effect: str = "Allow", version: int = 1) -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": effect,
                    "Action": "iot:Connect",
                    "Resource": f"arn:aws:iot:*:*:client/probe-{version}",
                }
            ],
        }
    )

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

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The legacy AttachPrincipalPolicy/DetachPrincipalPolicy pair must mutate the same
    state that ListPrincipalPolicies reads."""
    iot = ctx.client("iot")
    policy_name = ctx.unique_name("sim2real-behav-policy-principal-")
    iot.create_policy(policyName=policy_name, policyDocument=_policy_doc())
    ctx.on_cleanup(lambda _n=policy_name: _delete_policy(iot, _n))

    created = iot.create_keys_and_certificate(setAsActive=True)
    cert_id = created["certificateId"]
    cert_arn = created["certificateArn"]
    ctx.on_cleanup(lambda _n=cert_id: _delete_certificate(iot, _n))

    iot.attach_principal_policy(policyName=policy_name, principal=cert_arn)

    attached = _eventually(
        lambda: [
            p["policyName"]
            for p in iot.list_principal_policies(principal=cert_arn).get("policies", [])
        ],
        lambda ps: policy_name in ps,
        timeout_s=30,
        interval_s=2.0,
    )
    assert policy_name in attached, attached

    # The same attachment must also be visible through the modern reader.
    modern = [
        p["policyName"]
        for p in iot.list_attached_policies(target=cert_arn).get("policies", [])
    ]
    assert policy_name in modern, (
        f"legacy attach must be visible via ListAttachedPolicies, got {modern}"
    )

    targets = iot.list_targets_for_policy(policyName=policy_name).get("targets", [])
    assert cert_arn in targets, targets

    iot.detach_principal_policy(policyName=policy_name, principal=cert_arn)
    detached = _eventually(
        lambda: [
            p["policyName"]
            for p in iot.list_principal_policies(principal=cert_arn).get("policies", [])
        ],
        lambda ps: policy_name not in ps,
        timeout_s=30,
        interval_s=2.0,
    )
    assert policy_name not in detached, detached

    # The detach must also be visible through the modern reader.
    modern_after = [
        p["policyName"]
        for p in iot.list_attached_policies(target=cert_arn).get("policies", [])
    ]
    assert policy_name not in modern_after, (
        f"legacy detach must be visible via ListAttachedPolicies, got {modern_after}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
