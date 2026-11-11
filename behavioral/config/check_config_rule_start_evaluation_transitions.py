"""config-rule-start-evaluation-transitions."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "config-rule-start-evaluation-transitions"
GROUP = 'config-rule'
SERVICES = ['config']

# ===== helpers =====

_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException", "Throttling")


def _retry_throttled(fn, attempts=8, base_delay=2.0):
    """Call *fn*, retrying AWS Config throttling with exponential backoff.

    Config's control plane is aggressively rate limited; throttling is an
    infrastructure artifact, not a fidelity signal. Domain errors are re-raised.
    """
    last = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code not in _THROTTLE_CODES:
                raise
            last = exc
            time.sleep(base_delay * (2 ** min(attempt, 4)))
    raise last


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _delete_recorder_quiet(ctx, name):
    cfg = ctx.client("config")
    try:
        _retry_throttled(lambda: cfg.stop_configuration_recorder(ConfigurationRecorderName=name))
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchConfigurationRecorderException":
            raise
    try:
        _retry_throttled(lambda: cfg.delete_configuration_recorder(ConfigurationRecorderName=name))
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchConfigurationRecorderException":
            raise


def _delete_rule_quiet(ctx, name):
    try:
        ctx.client("config").delete_config_rule(ConfigRuleName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchConfigRuleException":
            raise


_CONFIG_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "config.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)
_CONFIG_MANAGED_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"


_RECORDER_FIELDS = ("name", "roleARN", "recordingGroup", "recordingMode")


def _clear_recorders_and_channels(ctx):
    """Delete every customer-managed recorder and every delivery channel.

    One cleanup restores them all: recorders, then channels, then recording on the
    recorders that were recording. Returns (recorder names, channel names) deleted.
    """
    cfg = ctx.client("config")
    recording = {
        st["name"]: st.get("recording", False)
        for st in cfg.describe_configuration_recorder_status().get("ConfigurationRecordersStatus", [])
    }
    recorders = [
        {k: r[k] for k in _RECORDER_FIELDS if k in r}
        for r in cfg.describe_configuration_recorders().get("ConfigurationRecorders", [])
        if not r.get("servicePrincipal")
    ]
    channels = cfg.describe_delivery_channels().get("DeliveryChannels", [])
    was_recording = [r["name"] for r in recorders if recording.get(r["name"], False)]

    for name in was_recording:
        _retry_throttled(lambda n=name: cfg.stop_configuration_recorder(ConfigurationRecorderName=n))
    for ch in channels:
        _retry_throttled(lambda n=ch["name"]: cfg.delete_delivery_channel(DeliveryChannelName=n))
    for rec in recorders:
        _retry_throttled(lambda n=rec["name"]: cfg.delete_configuration_recorder(ConfigurationRecorderName=n))

    def _restore():
        for rec in recorders:
            _retry_throttled(lambda r=rec: cfg.put_configuration_recorder(ConfigurationRecorder=r))
        # A channel can outlive its recorder, but it cannot be put back without one.
        for ch in channels if recorders else ():
            _retry_throttled(lambda c=ch: cfg.put_delivery_channel(DeliveryChannel=c))
        for name in was_recording:
            _retry_throttled(lambda n=name: cfg.start_configuration_recorder(ConfigurationRecorderName=n))

    ctx.on_cleanup(_restore)
    return [r["name"] for r in recorders], [c["name"] for c in channels]


def _create_config_role(ctx):
    """Create a role AWS Config can assume for recording; cleanup deletes it."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-cfg-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=_CONFIG_TRUST_POLICY,
        Description="sim2real behavioral fidelity probe role for AWS Config",
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.attach_role_policy(RoleName=name, PolicyArn=_CONFIG_MANAGED_POLICY_ARN)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_CONFIG_MANAGED_POLICY_ARN))
    return arn


def _ensure_recorder(ctx, rec_name):
    """Create this check's recorder with its own role, after clearing (and later restoring) any other."""
    cfg = ctx.client("config")
    _clear_recorders_and_channels(ctx)
    role_arn = _create_config_role(ctx)
    _retry_throttled(
        lambda: cfg.put_configuration_recorder(
            ConfigurationRecorder={
                "name": rec_name,
                "roleARN": role_arn,
                "recordingGroup": {"allSupported": True, "includeGlobalResourceTypes": False},
            }
        )
    )
    ctx.on_cleanup(lambda: _delete_recorder_quiet(ctx, rec_name))


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """StartConfigRulesEvaluation drives ACTIVE->EVALUATING->ACTIVE and updates evaluation-status timestamps."""
    _restore_config_recorder_on_teardown(ctx)
    cfg = ctx.client("config")
    rec_name = ctx.unique_name("sim2real-behav-cfg-rec-")
    rule_name = ctx.unique_name("sim2real-behav-cfg-rule-")

    _ensure_recorder(ctx, rec_name)
    cfg.put_config_rule(
        ConfigRule={
            "ConfigRuleName": rule_name,
            "Source": {"Owner": "AWS", "SourceIdentifier": "S3_BUCKET_PUBLIC_READ_PROHIBITED"},
        }
    )
    ctx.on_cleanup(lambda: _delete_rule_quiet(ctx, rule_name))

    def probe_eval_status():
        return cfg.describe_config_rule_evaluation_status(ConfigRuleNames=[rule_name])[
            "ConfigRulesEvaluationStatus"
        ][0]

    # a freshly-created rule has never started an evaluation; this is the "before"
    # half of the two-sided check that FirstEvaluationStarted flips.
    initial_status = probe_eval_status()
    assert initial_status["FirstEvaluationStarted"] is False, (
        f"expected a freshly-created rule to report no evaluation started yet, "
        f"got FirstEvaluationStarted={initial_status.get('FirstEvaluationStarted')!r}"
    )

    # rule must exist and be evaluable before triggering an on-demand evaluation
    def probe_active():
        return cfg.describe_config_rules(ConfigRuleNames=[rule_name])["ConfigRules"][0][
            "ConfigRuleState"
        ]

    _poll_until(probe_active, lambda s: s == "ACTIVE", timeout_s=20, interval_s=2)

    _retry_throttled(lambda: cfg.start_config_rules_evaluation(ConfigRuleNames=[rule_name]))

    # the independent terminal read: the evaluation-status side-channel must
    # flip to completed and stamp a real evaluation time, and the rule's own
    # state must settle back to ACTIVE -- the EVALUATING->ACTIVE half of the
    # transition the docstring claims.
    settled_status = _poll_until(
        probe_eval_status,
        lambda s: s.get("FirstEvaluationStarted") is True,
        timeout_s=60,
        interval_s=2,
        description="on-demand evaluation to report completion",
    )
    assert settled_status["ConfigRuleName"] == rule_name, (
        f"expected the evaluation status entry to name {rule_name!r}, "
        f"got: {settled_status.get('ConfigRuleName')!r}"
    )
    assert settled_status.get("LastSuccessfulInvocationTime") is not None, (
        f"expected LastSuccessfulInvocationTime to be stamped once Config has "
        f"invoked the rule for the on-demand evaluation, got: {settled_status}"
    )

    final_state = _poll_until(probe_active, lambda s: s == "ACTIVE", timeout_s=30, interval_s=2)
    assert final_state == "ACTIVE", (
        f"expected the rule to settle back to ACTIVE after the on-demand evaluation, "
        f"got: {final_state}"
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
