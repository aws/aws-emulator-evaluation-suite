"""config-rule-lifecycle."""

from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

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

_DEFAULT_RECORDING_GROUP = {"allSupported": True, "includeGlobalResourceTypes": False}

def _error(fn):
    """Call fn(); return its botocore (Error.Code, HTTP status, Error.Message). An unexpected
    SUCCESS raises, because an emulator ACCEPTING a call real AWS refuses must not read as a code
    mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return err.get("Code"), status, err.get("Message") or ""
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _absent_ok(fn, gone_code):
    """Cleanup step: run fn(); only the not-found code for a resource the check already
    deleted is tolerated, every other error propagates."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != gone_code:
            raise


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

def _ensure_config_role(ctx):
    """Create a per-run role ConfigurationRecorder.roleARN can name: trusts config.amazonaws.com
    and carries AWS_ConfigRole. Its cleanup detaches the policy and deletes the role, tolerating
    only NoSuchEntity."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-cfg-role-")[:64]
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=_CONFIG_TRUST_POLICY,
        Description="sim2real behavioral fidelity probe role for AWS Config",
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _absent_ok(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    iam.attach_role_policy(RoleName=name, PolicyArn=_CONFIG_MANAGED_POLICY_ARN)
    ctx.on_cleanup(
        lambda: _absent_ok(
            lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_CONFIG_MANAGED_POLICY_ARN),
            "NoSuchEntity",
        )
    )
    return arn

def _customer_recorder(ctx):
    """The account's existing customer-managed recorder, or None. Config allows one per region,
    so the check reuses it -- never stopping or deleting it -- rather than replacing it.
    Service-linked recorders (servicePrincipal set) are not customer-managed and are ignored."""
    cfg = ctx.client("config")
    recs = _retry_throttled(lambda: cfg.describe_configuration_recorders()).get("ConfigurationRecorders", [])
    for rec in recs:
        if not rec.get("servicePrincipal"):
            return rec
    return None

def _retry_role_propagation(fn, timeout_s=60, interval_s=3.0):
    # IAM is eventually consistent; a role Config was just told to trust can
    # still be rejected as insufficiently-permissioned for a bounded window
    # while the trust policy propagates. Retry only that specific rejection,
    # never a genuine permissions or validation error, until it resolves or
    # the deadline passes.
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "InsufficientPermissionsException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

def _create_recorder(ctx, name, recording_group=None, role_arn=None):
    cfg = ctx.client("config")
    recorder = {
        "name": name,
        "roleARN": role_arn or _ensure_config_role(ctx),
        "recordingGroup": recording_group or dict(_DEFAULT_RECORDING_GROUP),
    }
    _retry_throttled(
        lambda: _retry_role_propagation(
            lambda: cfg.put_configuration_recorder(ConfigurationRecorder=recorder)
        )
    )
    ctx.on_cleanup(
        lambda: _absent_ok(
            lambda: _retry_throttled(
                lambda: cfg.delete_configuration_recorder(ConfigurationRecorderName=name)
            ),
            "NoSuchConfigurationRecorderException",
        )
    )
    return name

CHECK = "config-rule-lifecycle"
GROUP = 'config-rule'
SERVICES = ['config']

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """PutConfigRule requires a recorder to exist, creates the rule in
    ACTIVE state, updates are idempotent in-place (no duplication), and
    after DeleteConfigRule the rule is fully gone."""
    _restore_config_recorder_on_teardown(ctx)
    cfg = ctx.client("config")
    # Account singleton: reuse an existing customer-managed recorder untouched, else create one
    # (and delete only that one at cleanup).
    if _customer_recorder(ctx) is None:
        _create_recorder(ctx, ctx.unique_name("sim2real-behav-cfg-recorder-"))

    rule_name = ctx.unique_name("sim2real-behav-cfg-rule-")
    cfg.put_config_rule(
        ConfigRule={
            "ConfigRuleName": rule_name,
            "Description": "initial description",
            "Source": {"Owner": "AWS", "SourceIdentifier": "S3_BUCKET_VERSIONING_ENABLED"},
        },
        Tags=[{"Key": "env", "Value": "test"}, {"Key": "owner", "Value": "fidelity"}],
    )
    ctx.on_cleanup(
        lambda a=rule_name: _absent_ok(
            lambda: cfg.delete_config_rule(ConfigRuleName=a), "NoSuchConfigRuleException"
        )
    )

    described = cfg.describe_config_rules(ConfigRuleNames=[rule_name])["ConfigRules"]
    assert len(described) == 1, described
    assert described[0]["ConfigRuleState"] == "ACTIVE", described[0]
    assert described[0]["Description"] == "initial description", described[0]
    arn_prefix = f"arn:aws:config:{ctx.region}:{ctx.account}:config-rule/"
    assert described[0].get("ConfigRuleArn", "").startswith(arn_prefix), (
        f"expected ConfigRuleArn to start with {arn_prefix!r}, got {described[0].get('ConfigRuleArn')!r}"
    )

    # idempotent update: same name, new description -> single rule updated
    # in place, not duplicated.
    cfg.put_config_rule(
        ConfigRule={
            "ConfigRuleName": rule_name,
            "Description": "updated description",
            "Source": {"Owner": "AWS", "SourceIdentifier": "S3_BUCKET_VERSIONING_ENABLED"},
        }
    )
    described = cfg.describe_config_rules(ConfigRuleNames=[rule_name])["ConfigRules"]
    assert len(described) == 1, described
    assert described[0]["Description"] == "updated description", described[0]
    assert described[0]["ConfigRuleState"] == "ACTIVE", described[0]

    cfg.delete_config_rule(ConfigRuleName=rule_name)
    # DeleteConfigRule is asynchronous: the rule first enters a DELETING state
    # and DescribeConfigRules keeps returning it until it is fully removed, only
    # then raising NoSuchConfigRuleException. Poll for the terminal state rather
    # than expecting the not-found error immediately.
    def _lookup():
        """The describe response while the resource is still listed, else its Error dict."""
        try:
            return {"Listed": cfg.describe_config_rules(ConfigRuleNames=[rule_name])}
        except ClientError as exc:
            err = dict(exc.response.get("Error", {}))
            err["HTTPStatusCode"] = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
            return err

    code_err = _poll_until(
        _lookup,
        lambda r: "Listed" not in r,
        timeout_s=180,
        interval_s=5,
    )
    assert code_err.get("Code") == "NoSuchConfigRuleException", code_err
    assert isinstance(code_err.get("HTTPStatusCode"), int) and 400 <= code_err.get("HTTPStatusCode") < 500, code_err
    expected_message = "One or more ConfigRules provided in the request are invalid. Please check the configRule names."
    assert code_err.get("Message") == expected_message, f'expected the message {expected_message!r}, got {code_err.get("Message")!r}'

    listed = [
        r["ConfigRuleName"]
        for page in cfg.get_paginator("describe_config_rules").paginate()
        for r in page.get("ConfigRules", [])
    ]
    assert rule_name not in listed, f"deleted rule {rule_name!r} is still listed by DescribeConfigRules"

    # the delete is not just gone-on-read: a further mutation against the
    # same dead id must also fail, not silently no-op.
    second_delete_code, second_delete_status, second_delete_message = _error(
        lambda: cfg.delete_config_rule(ConfigRuleName=rule_name)
    )
    assert second_delete_code == "NoSuchConfigRuleException", second_delete_code
    assert isinstance(second_delete_status, int) and 400 <= second_delete_status < 500, second_delete_status
    expected_message = f"The ConfigRule '{rule_name}' provided in the request is invalid. Please check the configRule name."
    assert second_delete_message == expected_message, f"expected the message {expected_message!r}, got {second_delete_message!r}"


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
