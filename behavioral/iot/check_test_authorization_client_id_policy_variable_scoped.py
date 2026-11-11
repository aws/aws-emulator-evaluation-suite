"""test-authorization-client-id-policy-variable-scoped."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "test-authorization-client-id-policy-variable-scoped"
GROUP = 'policy-lifecycle'
SERVICES = ['iot']


def _eventually(fn, predicate, timeout_s: int = 60, interval_s: float = 2.0):
    """Poll ``fn`` until ``predicate`` holds, tolerating transient exceptions.

    AWS IoT propagates writes asynchronously, so early reads can raise ResourceNotFoundException.
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
    """TestAuthorization substitutes ``${iot:ClientId}`` with the given clientId: the client's own
    topic is ALLOWED; another client's topic and the literal variable text are IMPLICIT_DENY."""
    iot = ctx.client("iot")
    account = ctx.client("sts").get_caller_identity()["Account"]

    created = iot.create_keys_and_certificate(setAsActive=True)
    cert_id = created["certificateId"]
    cert_arn = created["certificateArn"]
    ctx.on_cleanup(lambda _n=cert_id: _delete_certificate(iot, _n))

    mine = ctx.unique_name("sim2real-behav-client-mine-")
    theirs = ctx.unique_name("sim2real-behav-client-theirs-")
    prefix = f"arn:aws:iot:{ctx.region}:{account}:topic/sim2real/behav"

    policy_name = ctx.unique_name("sim2real-behav-policy-clientvar-")
    policy_arn = iot.create_policy(
        policyName=policy_name,
        policyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "iot:Publish",
                        "Resource": f"{prefix}/${{iot:ClientId}}/telemetry",
                    }
                ],
            }
        ),
    )["policyArn"]
    ctx.on_cleanup(lambda _n=policy_name: _delete_policy(iot, _n))
    iot.tag_resource(resourceArn=policy_arn, tags=[{"Key": "sim2real", "Value": CHECK}])
    iot.attach_policy(policyName=policy_name, target=cert_arn)

    def decide(client_id, resource):
        return iot.test_authorization(
            principal=cert_arn,
            clientId=client_id,
            authInfos=[{"actionType": "PUBLISH", "resources": [resource]}],
        )["authResults"][0]

    own = _eventually(
        lambda: decide(mine, f"{prefix}/{mine}/telemetry"),
        lambda r: r["authDecision"] == "ALLOWED",
        timeout_s=60,
    )
    assert own["authDecision"] == "ALLOWED", (
        f"PUBLISH to the client's own substituted topic must be ALLOWED, got {own['authDecision']}"
    )

    # the variable must not behave as a wildcard
    neighbour = decide(mine, f"{prefix}/{theirs}/telemetry")
    assert neighbour["authDecision"] == "IMPLICIT_DENY", (
        "${iot:ClientId} must scope the grant to the connecting client, not act as a wildcard; "
        f"clientId={mine} was {neighbour['authDecision']} on {theirs}'s topic"
    )
    assert not neighbour.get("allowed", {}).get("policies"), (
        f"no policy may be reported as allowing another client's topic: {neighbour.get('allowed')}"
    )

    # the variable must be substituted, not string-matched
    literal = decide(mine, f"{prefix}/${{iot:ClientId}}/telemetry")
    assert literal["authDecision"] == "IMPLICIT_DENY", (
        "the policy variable must be substituted, not string-matched; a request for the literal "
        f"'${{iot:ClientId}}' topic was {literal['authDecision']}"
    )

    again = decide(mine, f"{prefix}/{mine}/telemetry")
    assert again["authDecision"] == "ALLOWED", (
        f"the client's own topic must still be ALLOWED, got {again['authDecision']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
