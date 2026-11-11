"""test-authorization-subscribe-requires-topicfilter-resource."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "test-authorization-subscribe-requires-topicfilter-resource"
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
    """An ``iot:Subscribe`` grant on a ``topicfilter/`` ARN must not authorize a ``topic/`` resource, nor PUBLISH:
    Subscribe is evaluated against ``topicfilter/<filter>`` and Publish/Receive against ``topic/<topic>``,
    so a subscribe-only device policy never lets the device publish."""
    iot = ctx.client("iot")
    account = ctx.client("sts").get_caller_identity()["Account"]

    created = iot.create_keys_and_certificate(setAsActive=True)
    cert_id = created["certificateId"]
    cert_arn = created["certificateArn"]
    ctx.on_cleanup(lambda _n=cert_id: _delete_certificate(iot, _n))

    topic_path = "sim2real/behav/subscope"
    filter_arn = f"arn:aws:iot:{ctx.region}:{account}:topicfilter/{topic_path}"
    topic_arn = f"arn:aws:iot:{ctx.region}:{account}:topic/{topic_path}"

    policy_name = ctx.unique_name("sim2real-behav-policy-subonly-")
    iot.create_policy(
        policyName=policy_name,
        policyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "iot:Subscribe", "Resource": filter_arn}
                ],
            }
        ),
        tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda _n=policy_name: _delete_policy(iot, _n))
    iot.attach_policy(policyName=policy_name, target=cert_arn)

    def decide(action_type, resource):
        return iot.test_authorization(
            principal=cert_arn,
            authInfos=[{"actionType": action_type, "resources": [resource]}],
        )["authResults"][0]

    # Control: the grant it was written for. Attachment is eventually consistent.
    allowed = _eventually(
        lambda: decide("SUBSCRIBE", filter_arn),
        lambda r: r["authDecision"] == "ALLOWED",
        timeout_s=60,
    )
    assert allowed["authDecision"] == "ALLOWED", (
        f"SUBSCRIBE on the granted topicfilter must be ALLOWED, got {allowed['authDecision']}"
    )

    # Break exactly one thing: the resource NAMESPACE of the same subscribe request.
    wrong_ns = decide("SUBSCRIBE", topic_arn)
    assert wrong_ns["authDecision"] == "IMPLICIT_DENY", (
        "a topicfilter/ grant must not authorize SUBSCRIBE against a topic/ ARN; got "
        f"{wrong_ns['authDecision']} for {topic_arn}"
    )
    assert not wrong_ns.get("allowed", {}).get("policies"), (
        f"no policy may be reported as allowing the wrong-namespace request: {wrong_ns.get('allowed')}"
    )

    # Break exactly one thing: the ACTION. Subscribe must not confer Publish.
    wrong_action = decide("PUBLISH", topic_arn)
    assert wrong_action["authDecision"] == "IMPLICIT_DENY", (
        "an iot:Subscribe-only policy must not authorize PUBLISH; got "
        f"{wrong_action['authDecision']}"
    )
    assert not wrong_action.get("allowed", {}).get("policies"), (
        f"no policy may be reported as allowing PUBLISH under a Subscribe-only grant: "
        f"{wrong_action.get('allowed')}"
    )

    # Control still holds after the negatives — the decision engine is stateless here.
    again = decide("SUBSCRIBE", filter_arn)
    assert again["authDecision"] == "ALLOWED", (
        f"the granted SUBSCRIBE must still be ALLOWED, got {again['authDecision']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
