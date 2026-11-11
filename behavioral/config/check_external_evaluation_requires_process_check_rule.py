"""external-evaluation-requires-process-check-rule."""

from __future__ import annotations

import time
from datetime import datetime, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError


def _retry_throttled(fn, attempts=8, base_delay=2.0):
    # Config's control plane has a very low burst limit; retry throttles only.
    last = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code not in ("ThrottlingException", "TooManyRequestsException"):
                raise
            last = exc
            time.sleep(base_delay * (2 ** min(attempt, 4)))
    raise last


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _config_slr_arn(ctx):
    """The AWS Config service-linked role's ARN; the check creates it when the account lacks it."""
    iam = ctx.client("iam")
    try:
        return iam.create_service_linked_role(AWSServiceName="config.amazonaws.com")["Role"]["Arn"]
    except ClientError as exc:
        err = exc.response.get("Error", {})
        if err.get("Code") != "InvalidInput" or "has been taken" not in err.get("Message", ""):
            raise
    return iam.get_role(RoleName="AWSServiceRoleForConfig")["Role"]["Arn"]


def _ensure_recorder_exists(ctx):
    """Guarantee a configuration recorder EXISTS without touching one we did not
    create; never start one (account-wide, billed per configuration item)."""
    cfg = ctx.client("config")
    existing = _retry_throttled(cfg.describe_configuration_recorders).get(
        "ConfigurationRecorders", []
    )
    if existing:
        return existing[0]["name"], False

    role_arn = _config_slr_arn(ctx)

    recorder = ctx.unique_name("sim2real-behav-cfg-recorder-")
    deadline = time.monotonic() + 120
    last = None
    while time.monotonic() < deadline:
        try:
            _retry_throttled(
                lambda: cfg.put_configuration_recorder(
                    ConfigurationRecorder={
                        "name": recorder,
                        "roleARN": role_arn,
                        # An inclusion recording group must name at least one type (an empty
                        # list is InvalidRecordingGroupException); one narrow type keeps it cheap.
                        "recordingGroup": {
                            "allSupported": False,
                            "resourceTypes": ["AWS::S3::Bucket"],
                        },
                    }
                )
            )
            break
        except ClientError as exc:
            last = exc
            if exc.response.get("Error", {}).get("Code", "") not in (
                "InsufficientPermissionsException",
                "InvalidRoleException",
                "ValidationException",
            ):
                raise
            time.sleep(5)
    else:
        raise AssertionError(
            f"could not create a configuration recorder within 120s: {last!r}"
        )
    ctx.on_cleanup(
        lambda r=recorder: _retry_throttled(
            lambda: cfg.delete_configuration_recorder(ConfigurationRecorderName=r)
        )
    )
    return recorder, True


CHECK = "external-evaluation-requires-process-check-rule"
GROUP = 'compliance'
SERVICES = ['config']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """PutExternalEvaluation is refused on a managed rule (InvalidParameterValueException) and on a
    missing rule (NoSuchConfigRuleException), and records no evaluation result in either case.
    """
    _restore_config_recorder_on_teardown(ctx)
    cfg = ctx.client("config")
    _ensure_recorder_exists(ctx)

    resource_id = ctx.unique_name("sim2real-behav-cfg-external-res-")
    external = {
        "ComplianceResourceType": "AWS::S3::Bucket",
        "ComplianceResourceId": resource_id,
        "ComplianceType": "NON_COMPLIANT",
        "Annotation": "sim2real fidelity probe: must never be accepted",
        "OrderingTimestamp": datetime.now(timezone.utc),
    }

    # Leg 1: a rule that does not exist. Distinct, modelled, unambiguous.
    absent_rule = ctx.unique_name("sim2real-behav-cfg-absent-rule-")
    code, message = _error(
        lambda: cfg.put_external_evaluation(
            ConfigRuleName=absent_rule, ExternalEvaluation=external
        )
    )
    assert code == "NoSuchConfigRuleException", (
        f"PutExternalEvaluation against a nonexistent rule must be "
        f"NoSuchConfigRuleException; got {code!r}"
    )
    assert message == (
        f"The ConfigRule '{absent_rule}' provided in the request is invalid. Please check the "
        "configRule name."
    ), message

    # Leg 2: a rule that DOES exist but is an AWS managed rule, not a process
    # check. Scoped to a tag key that cannot exist so the rule evaluates nothing
    # and bills nothing.
    inert_tag_key = ctx.unique_name("sim2real-behav-cfg-noscope-")
    managed = ctx.unique_name("sim2real-behav-cfg-rule-")
    _retry_throttled(
        lambda: cfg.put_config_rule(
            ConfigRule={
                "ConfigRuleName": managed,
                "Source": {"Owner": "AWS", "SourceIdentifier": "S3_BUCKET_VERSIONING_ENABLED"},
                "Scope": {"TagKey": inert_tag_key},
            }
        )
    )
    ctx.on_cleanup(
        lambda n=managed: _retry_throttled(
            lambda: cfg.delete_config_rule(ConfigRuleName=n)
        )
    )
    active_rule = _poll_until(
        lambda: _retry_throttled(
            lambda: cfg.describe_config_rules(ConfigRuleNames=[managed])
        )["ConfigRules"][0],
        lambda r: r.get("ConfigRuleState") == "ACTIVE",
        timeout_s=120,
        interval_s=3.0,
        description=f"managed rule {managed} reaches ACTIVE",
    )
    _retry_throttled(
        lambda: cfg.tag_resource(
            ResourceArn=active_rule["ConfigRuleArn"],
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
    )

    code, message = _error(
        lambda: cfg.put_external_evaluation(
            ConfigRuleName=managed, ExternalEvaluation=external
        )
    )
    assert code == "InvalidParameterValueException", (
        f"PutExternalEvaluation against an existing AWS managed rule must be refused "
        f"with InvalidParameterValueException -- the rule exists, so the refusal is "
        f"about its type; got {code!r} (message {message!r})"
    )
    assert message == (
        "This API can only be applied to rules with sourceIdentifier as AWS_CONFIG_PROCESS_CHECK."
    ), message
    assert code != "NoSuchConfigRuleException", (
        "the two refusal conditions must not collapse onto one code"
    )

    # Effect absent: no compliance verdict may have been recorded for the
    # resource we tried to write, and the rule's own compliance must not have
    # been flipped to NON_COMPLIANT.
    details = _retry_throttled(
        lambda: cfg.get_compliance_details_by_config_rule(ConfigRuleName=managed)
    )
    written = [
        r
        for r in details.get("EvaluationResults", [])
        if r.get("EvaluationResultIdentifier", {})
        .get("EvaluationResultQualifier", {})
        .get("ResourceId")
        == resource_id
    ]
    assert written == [], (
        f"a refused PutExternalEvaluation must record no evaluation result; found "
        f"{written!r}"
    )
    by_rule = _retry_throttled(
        lambda: cfg.describe_compliance_by_config_rule(ConfigRuleNames=[managed])
    )["ComplianceByConfigRules"]
    assert len(by_rule) == 1, by_rule
    assert by_rule[0]["Compliance"]["ComplianceType"] != "NON_COMPLIANT", (
        f"a refused external verdict must not mark the rule NON_COMPLIANT; got "
        f"{by_rule[0]['Compliance']!r}"
    )

    # Control still works: the rule is intact and still ACTIVE after two refusals.
    after = _retry_throttled(
        lambda: cfg.describe_config_rules(ConfigRuleNames=[managed])
    )["ConfigRules"][0]
    assert after["ConfigRuleState"] == "ACTIVE", after
    assert after["Source"]["Owner"] == "AWS", after["Source"]


def _restore_config_recorder_on_teardown(ctx) -> None:
    """The Config recorder and delivery channel exist once per account and Region: read them now
    and, in a teardown that runs after the check's own, put back exactly what was there."""
    import time

    from botocore.exceptions import ClientError

    cfg = ctx.client("config")

    def _call(fn):
        deadline = time.monotonic() + 60.0
        while True:
            try:
                return fn()
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ThrottlingException" or time.monotonic() > deadline:
                    raise
                time.sleep(2.0)

    def _recorders():
        found = _call(cfg.describe_configuration_recorders)["ConfigurationRecorders"]
        return [r for r in found if not r.get("servicePrincipal")]

    recorders = _recorders()
    statuses = _call(cfg.describe_configuration_recorder_status)["ConfigurationRecordersStatus"]
    recording = {s["name"] for s in statuses if s.get("recording")}
    channels = _call(cfg.describe_delivery_channels)["DeliveryChannels"]
    fields = ("name", "roleARN", "recordingGroup", "recordingMode")

    def _restore() -> None:
        now = _recorders()
        for r in now:
            _call(lambda n=r["name"]: cfg.stop_configuration_recorder(ConfigurationRecorderName=n))
        kept = {c["name"] for c in channels}
        for c in _call(cfg.describe_delivery_channels)["DeliveryChannels"]:
            if c["name"] not in kept:
                _call(lambda n=c["name"]: cfg.delete_delivery_channel(DeliveryChannelName=n))
        kept = {r["name"] for r in recorders}
        for r in now:
            if r["name"] not in kept:
                _call(lambda n=r["name"]: cfg.delete_configuration_recorder(ConfigurationRecorderName=n))
        for r in recorders:
            body = {k: v for k, v in r.items() if k in fields}
            _call(lambda b=body: cfg.put_configuration_recorder(ConfigurationRecorder=b))
        for c in channels:
            _call(lambda c=c: cfg.put_delivery_channel(DeliveryChannel=c))
        for r in recorders:
            if r["name"] in recording:
                _call(lambda n=r["name"]: cfg.start_configuration_recorder(ConfigurationRecorderName=n))

    ctx.on_cleanup(_restore)



if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
