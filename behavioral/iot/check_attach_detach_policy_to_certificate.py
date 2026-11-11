"""attach-detach-policy-to-certificate."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "attach-detach-policy-to-certificate"
GROUP = 'policy-lifecycle'
SERVICES = ['iot']

_ALLOW_ALL_DOC = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "iot:Connect", "Resource": "*"}],
    }
)

def _delete_certificate(iot, cert_id):
    """Teardown: detach policies/things, deactivate, then force-delete; a missing certificate is clean."""
    try:
        cert_arn = iot.describe_certificate(certificateId=cert_id)[
            "certificateDescription"
        ]["certificateArn"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        cert_arn = None
    if cert_arn:
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

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AttachPolicy/DetachPolicy on a certificate target updates ListAttachedPolicies."""
    iot = ctx.client("iot")
    name = ctx.unique_name("sim2real-behav-policy-attach-")
    iot.create_policy(policyName=name, policyDocument=_ALLOW_ALL_DOC)
    ctx.on_cleanup(lambda _n=name: _delete_policy(iot, _n))

    created = iot.create_keys_and_certificate(setAsActive=True)
    cert_id = created["certificateId"]
    cert_arn = created["certificateArn"]
    ctx.on_cleanup(lambda _n=cert_id: _delete_certificate(iot, _n))

    iot.attach_policy(policyName=name, target=cert_arn)
    attached = iot.list_attached_policies(target=cert_arn).get("policies", [])
    assert any(p["policyName"] == name for p in attached), (
        f"expected {name!r} in ListAttachedPolicies(target=cert), got {attached}"
    )

    # Independent side-channel: the same attachment must be visible from the policy's
    # own target list, not only the certificate's attached-policy list.
    targets = iot.list_targets_for_policy(policyName=name).get("targets", [])
    assert cert_arn in targets, (
        f"expected {cert_arn!r} in ListTargetsForPolicy({name!r}), got {targets}"
    )

    iot.detach_policy(policyName=name, target=cert_arn)
    attached_after = iot.list_attached_policies(target=cert_arn).get("policies", [])
    assert not any(p["policyName"] == name for p in attached_after), (
        f"expected {name!r} absent from ListAttachedPolicies(target=cert), got {attached_after}"
    )

    targets_after = iot.list_targets_for_policy(policyName=name).get("targets", [])
    assert cert_arn not in targets_after, (
        f"expected {cert_arn!r} absent from ListTargetsForPolicy({name!r}), got {targets_after}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
