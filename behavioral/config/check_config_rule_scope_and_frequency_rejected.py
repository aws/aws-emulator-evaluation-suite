"""config-rule-scope-and-frequency-rejected."""

from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

_CONFIG_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "config.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)
_CONFIG_MANAGED_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"


def _retry_throttled(fn, attempts=8, base_delay=2.0):
    # Config's control plane has a very low burst limit; churning recorders/rules/
    # delivery-channels across checks reliably trips ThrottlingException. Retry those
    # transparently while re-raising any domain error a check asserts on.
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
    """Call fn(); return its botocore (Error.Code, Error.Message). An unexpected SUCCESS raises,
    because an emulator ACCEPTING a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _trusts_config_service(doc):
    import urllib.parse as _up

    if isinstance(doc, str):
        try:
            doc = json.loads(_up.unquote(doc))
        except Exception:
            return False
    if not isinstance(doc, dict):
        return False
    for stmt in doc.get("Statement", []):
        principal = stmt.get("Principal", {})
        svc = principal.get("Service") if isinstance(principal, dict) else None
        svcs = svc if isinstance(svc, list) else [svc]
        if "config.amazonaws.com" in svcs:
            return True
    return False


def _ensure_recorder_exists(ctx):
    """Guarantee a configuration recorder EXISTS without touching one we did not
    create. PutConfigRule fails with NoAvailableConfigurationRecorderException
    when none exists, but it does NOT require one to be RUNNING -- and a running
    recorder bills a configuration item for every supported resource in the
    account, for every tenant sharing it."""
    cfg = ctx.client("config")
    existing = _retry_throttled(cfg.describe_configuration_recorders).get(
        "ConfigurationRecorders", []
    )
    if existing:
        return existing[0]["name"], False

    iam = ctx.client("iam")
    role_arn = None
    for name in ("config-role", "AWSConfigRole", "AWSServiceRoleForConfig"):
        try:
            role = iam.get_role(RoleName=name)["Role"]
        except ClientError:
            continue
        if _trusts_config_service(role.get("AssumeRolePolicyDocument")):
            role_arn = role["Arn"]
            break
    if role_arn is None:
        created_role = ctx.unique_name("sim2real-behav-cfg-role-")
        try:
            role_arn = iam.create_role(
                RoleName=created_role,
                AssumeRolePolicyDocument=_CONFIG_TRUST_POLICY,
                Description="sim2real behavioral fidelity probe role for AWS Config",
            )["Role"]["Arn"]
        except ClientError as exc:
            raise AssertionError(
                "no AWS Config service role exists in this account and the caller "
                "lacks iam:CreateRole, so no configuration recorder can be created: "
                f"{exc.response.get('Error', {}).get('Code')}"
            ) from exc
        ctx.on_cleanup(lambda r=created_role: iam.delete_role(RoleName=r))
        try:
            iam.attach_role_policy(
                RoleName=created_role, PolicyArn=_CONFIG_MANAGED_POLICY_ARN
            )
            ctx.on_cleanup(
                lambda r=created_role: iam.detach_role_policy(
                    RoleName=r, PolicyArn=_CONFIG_MANAGED_POLICY_ARN
                )
            )
        except ClientError:
            pass

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
                        # An INCLUSION recording group must name at least one type:
                        # allSupported=False with an EMPTY resourceTypes list is refused
                        # with InvalidRecordingGroupException, as is
                        # allSupported=True alongside resourceTypes. One narrow type keeps
                        # the prerequisite recorder cheap.
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


CHECK = "config-rule-scope-and-frequency-rejected"
GROUP = 'config-rule'
SERVICES = ['config']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """PutConfigRule fails with InvalidParameterValueException and a distinct exact message for a Scope
    ComplianceResourceId without one ComplianceResourceType, a MaximumExecutionFrequency on a
    change-triggered managed rule, and SourceDetails on an AWS managed rule, leaving no rule behind."""
    _restore_config_recorder_on_teardown(ctx)
    cfg = ctx.client("config")
    _ensure_recorder_exists(ctx)

    # Scope the control rule by a tag key that cannot exist, so the rule matches
    # zero resources and performs zero (billable) evaluations regardless of
    # whether the account's recorder happens to be running.
    inert_tag_key = ctx.unique_name("sim2real-behav-cfg-noscope-")
    control = ctx.unique_name("sim2real-behav-cfg-rule-")
    _retry_throttled(
        lambda: cfg.put_config_rule(
            ConfigRule={
                "ConfigRuleName": control,
                "Source": {"Owner": "AWS", "SourceIdentifier": "S3_BUCKET_VERSIONING_ENABLED"},
                "Scope": {"TagKey": inert_tag_key},
            }
        )
    )
    ctx.on_cleanup(
        lambda n=control: _retry_throttled(
            lambda: cfg.delete_config_rule(ConfigRuleName=n)
        )
    )
    described = _poll_until(
        lambda: _retry_throttled(
            lambda: cfg.describe_config_rules(ConfigRuleNames=[control])
        )["ConfigRules"][0],
        lambda r: r.get("ConfigRuleState") == "ACTIVE",
        timeout_s=120,
        interval_s=3.0,
        description=f"control rule {control} reaches ACTIVE",
    )
    assert described["Scope"]["TagKey"] == inert_tag_key, described
    assert "MaximumExecutionFrequency" not in described, (
        f"a change-triggered managed rule must not acquire a default "
        f"MaximumExecutionFrequency, got {described.get('MaximumExecutionFrequency')!r}"
    )

    # The third element is the exact refusal message. All three
    # legs share InvalidParameterValueException and the message is prose describing
    # the conflict, not the request field name -- only the SourceDetails leg names its
    # field. The message is the only discriminator between the legs.
    legs = [
        (
            "ComplianceResourceId without exactly one ComplianceResourceTypes",
            {
                "Source": {
                    "Owner": "AWS",
                    "SourceIdentifier": "S3_BUCKET_VERSIONING_ENABLED",
                },
                "Scope": {
                    "ComplianceResourceId": "sim2real-behav-cfg-scoped-bucket",
                    "ComplianceResourceTypes": ["AWS::S3::Bucket", "AWS::EC2::Volume"],
                },
            },
            "A single resourceType should be provided when resourceId is provided in scope",
        ),
        (
            "MaximumExecutionFrequency on a change-triggered managed rule",
            {
                "Source": {
                    "Owner": "AWS",
                    "SourceIdentifier": "S3_BUCKET_VERSIONING_ENABLED",
                },
                "Scope": {"TagKey": inert_tag_key},
                "MaximumExecutionFrequency": "TwentyFour_Hours",
            },
            "A maximum execution frequency for this rule is not allowed because only a "
            "change in resources triggers this managed rule.",
        ),
        (
            "SourceDetails supplied for an Owner=AWS managed rule",
            {
                "Source": {
                    "Owner": "AWS",
                    "SourceIdentifier": "S3_BUCKET_VERSIONING_ENABLED",
                    "SourceDetails": [
                        {
                            "EventSource": "aws.config",
                            "MessageType": "ConfigurationItemChangeNotification",
                        }
                    ],
                },
                "Scope": {"TagKey": inert_tag_key},
            },
            "The provided SourceDetails are not valid. The SourceDetails should be "
            "null/empty if the owner is AWS. The SourceDetails should be provided if the "
            "owner is CUSTOM_LAMBDA or CUSTOM_POLICY. Only "
            "ConfigurationItemChangeNotification or "
            "OversizedConfigurationItemChangeNotification is allowed when the owner is "
            "CUSTOM_POLICY.",
        ),
    ]
    for description, body, expected_message in legs:
        name = ctx.unique_name("sim2real-behav-cfg-rule-bad-")
        rule = dict(body, ConfigRuleName=name)
        code, message = _error(
            lambda r=rule: _retry_throttled(lambda: cfg.put_config_rule(ConfigRule=r))
        )
        assert code == "InvalidParameterValueException", (
            f"{description} must be refused with InvalidParameterValueException; "
            f"got {code!r} (message {message!r})"
        )
        assert message == expected_message, (
            f"{description}: the refusal must read {expected_message!r} so the caller "
            f"can tell it apart from the other two InvalidParameterValueException "
            f"conditions; got {message!r}"
        )
        # Effect absent: no rule of that name may exist.
        missing, missing_message = _error(
            lambda n=name: cfg.describe_config_rules(ConfigRuleNames=[n])
        )
        assert missing == "NoSuchConfigRuleException", (
            f"{description} was refused but a rule named {name} exists "
            f"(DescribeConfigRules returned {missing!r})"
        )
        assert missing_message == (
            "One or more ConfigRules provided in the request are invalid. Please check the "
            "configRule names."
        ), missing_message

    # Control still works: the accepted rule is untouched and still ACTIVE.
    after = _retry_throttled(
        lambda: cfg.describe_config_rules(ConfigRuleNames=[control])
    )["ConfigRules"][0]
    assert after["ConfigRuleState"] == "ACTIVE", after
    assert after["Scope"]["TagKey"] == inert_tag_key, after
    assert "MaximumExecutionFrequency" not in after, (
        f"a refused MaximumExecutionFrequency must not have leaked onto the control "
        f"rule, got {after!r}"
    )


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
