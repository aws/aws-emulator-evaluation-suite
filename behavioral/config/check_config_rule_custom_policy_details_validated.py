"""config-rule-custom-policy-details-validated."""

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

# A minimal, valid Guard 2.x rule set. Its content is irrelevant to the rule's
# verdict here (the rule is scoped to a tag key that cannot exist, so it evaluates
# nothing and bills nothing); what matters is that it round-trips byte-exact.
_GUARD_POLICY_TEXT = 'rule sim2real_configuration_present {\n    configuration exists\n}\n'


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
    create; never start one (account-wide, billed per configuration item)."""
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
                Tags=[
                    {"Key": "sim2real:managed", "Value": "true"},
                    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
                ],
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
                    },
                    Tags=[
                        {"Key": "sim2real:managed", "Value": "true"},
                        {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
                    ],
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


CHECK = "config-rule-custom-policy-details-validated"
GROUP = 'config-rule'
SERVICES = ['config']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """PutConfigRule with Owner CUSTOM_POLICY fails without CustomPolicyDetails, with a PolicyRuntime other
    than guard-2.x.x, and with uncompilable Guard text, each with its exact code and message and no rule
    left; an accepted rule returns its PolicyText byte for byte from GetCustomRulePolicy."""
    _restore_config_recorder_on_teardown(ctx)
    cfg = ctx.client("config")
    _ensure_recorder_exists(ctx)

    # Scoped to a tag key that cannot exist, so the Guard policy is never actually
    # run against any resource and no rule evaluation is billed.
    inert_tag_key = ctx.unique_name("sim2real-behav-cfg-noscope-")
    source_details = [
        {
            "EventSource": "aws.config",
            "MessageType": "ConfigurationItemChangeNotification",
        }
    ]

    # Control first: a well-formed CUSTOM_POLICY rule is accepted and reaches ACTIVE.
    control = ctx.unique_name("sim2real-behav-cfg-guard-rule-")
    _retry_throttled(
        lambda: cfg.put_config_rule(
            ConfigRule={
                "ConfigRuleName": control,
                "Scope": {"TagKey": inert_tag_key},
                "Source": {
                    "Owner": "CUSTOM_POLICY",
                    "SourceDetails": source_details,
                    "CustomPolicyDetails": {
                        "PolicyRuntime": "guard-2.x.x",
                        "PolicyText": _GUARD_POLICY_TEXT,
                        "EnableDebugLogDelivery": False,
                    },
                },
            },
            Tags=[
                {"Key": "sim2real:managed", "Value": "true"},
                {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
            ],
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
        description=f"CUSTOM_POLICY rule {control} reaches ACTIVE",
    )
    assert described["Source"]["Owner"] == "CUSTOM_POLICY", described["Source"]
    assert (
        described["Source"]["CustomPolicyDetails"]["PolicyRuntime"] == "guard-2.x.x"
    ), described["Source"]["CustomPolicyDetails"]
    assert "SourceIdentifier" not in described["Source"], (
        f"a CUSTOM_POLICY rule must not acquire a SourceIdentifier, got "
        f"{described['Source']!r}"
    )

    # The policy document must round-trip byte-exact through the dedicated
    # accessor -- no whitespace normalisation, no re-indentation, no truncation.
    fetched = _retry_throttled(lambda: cfg.get_custom_rule_policy(ConfigRuleName=control))
    assert fetched["PolicyText"] == _GUARD_POLICY_TEXT, (
        "GetCustomRulePolicy must return the Guard document byte-for-byte; got "
        f"{fetched['PolicyText']!r} for {_GUARD_POLICY_TEXT!r}"
    )

    # One Guard parser diagnostic for the invalid PolicyText leg; AWS repeats it twice.
    _GUARD_PARSE_ERROR = (
        "Parser Error when parsing Parsing Error Error parsing file  at line 1 at column 1, "
        "when handling , fragment this is not guard syntax {{{ <<< "
    )
    # (description, request body, expected error CODE, exact refusal message).
    # The three legs do NOT share one code. Owner/PolicyText semantics are Config's own
    # InvalidParameterValueException, but PolicyRuntime carries a Smithy @pattern (guard\-2\.x\.x),
    # so a bad runtime is caught by the generic request validator and comes back as
    # ValidationException naming the member path. Both code AND message are asserted per leg.
    legs = [
        (
            "Owner=CUSTOM_POLICY with no CustomPolicyDetails",
            {
                "Scope": {"TagKey": inert_tag_key},
                "Source": {"Owner": "CUSTOM_POLICY", "SourceDetails": source_details},
            },
            "InvalidParameterValueException",
            "CustomPolicyDetails is required when Owner is CUSTOM_POLICY",
        ),
        (
            "PolicyRuntime that is not guard-2.x.x",
            {
                "Scope": {"TagKey": inert_tag_key},
                "Source": {
                    "Owner": "CUSTOM_POLICY",
                    "SourceDetails": source_details,
                    "CustomPolicyDetails": {
                        "PolicyRuntime": "guard-1.x.x",
                        "PolicyText": _GUARD_POLICY_TEXT,
                    },
                },
            },
            "ValidationException",
            "1 validation error detected: Value 'guard-1.x.x' at "
            "'configRule.source.customPolicyDetails.policyRuntime' failed to satisfy "
            "constraint: Member must satisfy regular expression pattern: guard\\-2\\.x\\.x",
        ),
        (
            "PolicyText that is not valid Guard",
            {
                "Scope": {"TagKey": inert_tag_key},
                "Source": {
                    "Owner": "CUSTOM_POLICY",
                    "SourceDetails": source_details,
                    "CustomPolicyDetails": {
                        "PolicyRuntime": "guard-2.x.x",
                        "PolicyText": "this is not guard syntax {{{ <<< ",
                    },
                },
            },
            "InvalidParameterValueException",
            "The PolicyText provided is invalid. Runtime: guard-2.x.x, Reason: Parsing error "
            "handling rule, Error = " + _GUARD_PARSE_ERROR + "\n\nError occurred "
            + _GUARD_PARSE_ERROR + "\n.",
        ),
    ]
    for description, body, expected_code, expected_message in legs:
        name = ctx.unique_name("sim2real-behav-cfg-guard-bad-")
        rule = dict(body, ConfigRuleName=name)
        code, message = _error(
            lambda r=rule: _retry_throttled(lambda: cfg.put_config_rule(ConfigRule=r))
        )
        assert code == expected_code, (
            f"{description} must be refused with {expected_code}; "
            f"got {code!r} (message {message!r})"
        )
        assert message == expected_message, (
            f"{description}: the refusal must read {expected_message!r} -- two of the "
            f"three legs share InvalidParameterValueException, so the message is the "
            f"only signal that distinguishes them; got {message!r}"
        )
        # Effect absent: neither the rule nor a policy document may exist.
        missing, missing_message = _error(
            lambda n=name: cfg.describe_config_rules(ConfigRuleNames=[n])
        )
        assert missing == "NoSuchConfigRuleException", (
            f"{description} was refused but rule {name} exists (got {missing!r})"
        )
        assert missing_message == (
            "One or more ConfigRules provided in the request are invalid. Please check the "
            "configRule names."
        ), missing_message
        orphan, orphan_message = _error(lambda n=name: cfg.get_custom_rule_policy(ConfigRuleName=n))
        assert orphan == "NoSuchConfigRuleException", (
            f"{description} was refused but GetCustomRulePolicy resolves {name} "
            f"(got {orphan!r}) -- a refused Put must not persist a policy document"
        )
        assert orphan_message == (
            f"The ConfigRule '{name}' provided in the request is invalid. "
            "Please check the configRule name."
        ), orphan_message

    # Control still works and is byte-identical after three refusals.
    again = _retry_throttled(lambda: cfg.get_custom_rule_policy(ConfigRuleName=control))
    assert again["PolicyText"] == _GUARD_POLICY_TEXT, again


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
