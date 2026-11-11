"""proactive-resource-evaluation-reaches-terminal-state."""

from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

# ===== helpers =====


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


def _retry_role_propagation(fn, *, description, timeout_s=60.0, interval_s=3.0):
    """Bounded retry on Config's InvalidRoleException, the specific shape a
    just-created IAM role produces until it has propagated. Never a bare sleep --
    a deadline, a stated reason, and it raises on timeout rather than proceeding
    with an unusable recorder."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "InvalidRoleException":
                raise
            last = exc
            time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last error: {last!r}")


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
# A Guard policy that every configuration satisfies -- the point is that a rule
# exists in PROACTIVE mode for AWS::S3::Bucket, not what it decides.
_GUARD_POLICY_TEXT = "rule sim2real_configuration_present {\n    configuration exists\n}\n"


def _ensure_proactive_rule(ctx, resource_type):
    """Create the prerequisites a PROACTIVE StartResourceEvaluation needs.

    On real AWS, StartResourceEvaluation is NOT a standalone surface. With
    no PROACTIVE-mode rule for the resource type the evaluation still mints an id
    and still reaches a terminal state, but that state is FAILED with FailureReason
    "No Config rule is enabled in proactive mode for the given resource type." And
    PutConfigRule itself is refused with NoAvailableConfigurationRecorderException
    until a configuration recorder exists -- so BOTH a recorder and a rule are
    prerequisites.

    Each prerequisite is created here and torn down via ctx.on_cleanup registered
    immediately after its create, so LIFO yields the only order the services
    accept (rule, then recorder, then role).

    No AWS-managed rule supports PROACTIVE mode for AWS::S3::Bucket (all five S3
    managed rules tried are refused with "The AWS Config rule you are enabling does
    not support the specified evaluation modes"), so the rule is Owner=CUSTOM_POLICY
    with a trivially-true Guard policy.
    """
    cfg = ctx.client("config")
    iam = ctx.client("iam")

    role_name = ctx.unique_name("sim2real-behav-cfg-proactive-role-")
    _RESOURCE_TAGS = [{"Key": "env", "Value": "test"}, {"Key": "owner", "Value": "fidelity"}]
    try:
        role_arn = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=_CONFIG_TRUST_POLICY,
            Description="sim2real behavioral fidelity probe role for AWS Config",
            Tags=_RESOURCE_TAGS,
        )["Role"]["Arn"]
    except ClientError as exc:
        raise AssertionError(
            "the caller cannot create the AWS Config service role a configuration "
            "recorder requires, and PutConfigRule is refused without a recorder: "
            f"{exc.response.get('Error', {}).get('Code')}"
        ) from exc
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_CONFIG_MANAGED_POLICY_ARN)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_CONFIG_MANAGED_POLICY_ARN)
    )

    recorder = ctx.unique_name("sim2real-behav-cfg-proactive-recorder-")

    def _put_recorder():
        return cfg.put_configuration_recorder(
            ConfigurationRecorder={
                "name": recorder,
                "roleARN": role_arn,
                # An INCLUSION recording group must name at least one type
                # (allSupported=False with an empty resourceTypes list is refused
                # with InvalidRecordingGroupException); one narrow type keeps the
                # prerequisite recorder cheap. The recorder is never STARTED.
                "recordingGroup": {"allSupported": False, "resourceTypes": [resource_type]},
            },
            Tags=_RESOURCE_TAGS,
        )

    # IAM is eventually consistent; Config's pass-role validation refuses the
    # brand-new role with InvalidRoleException until it has propagated. Bounded
    # retry on that specific error, never a bare sleep.
    _retry_role_propagation(
        _put_recorder,
        description=f"IAM role {role_name} propagates so the Config recorder can PassRole it",
    )
    ctx.on_cleanup(
        lambda: _retry_throttled(
            lambda: cfg.delete_configuration_recorder(ConfigurationRecorderName=recorder)
        )
    )

    rule = ctx.unique_name("sim2real-behav-cfg-proactive-rule-")
    _retry_throttled(
        lambda: cfg.put_config_rule(
            ConfigRule={
                "ConfigRuleName": rule,
                "Scope": {"ComplianceResourceTypes": [resource_type]},
                "Source": {
                    "Owner": "CUSTOM_POLICY",
                    "CustomPolicyDetails": {
                        "PolicyRuntime": "guard-2.x.x",
                        "PolicyText": _GUARD_POLICY_TEXT,
                        "EnableDebugLogDelivery": False,
                    },
                    "SourceDetails": [
                        {
                            "EventSource": "aws.config",
                            "MessageType": "ConfigurationItemChangeNotification",
                        }
                    ],
                },
                "EvaluationModes": [{"Mode": "PROACTIVE"}],
            },
            Tags=_RESOURCE_TAGS,
        )
    )
    ctx.on_cleanup(lambda: _retry_throttled(lambda: cfg.delete_config_rule(ConfigRuleName=rule)))
    described = _poll_until(
        lambda: _retry_throttled(
            lambda: cfg.describe_config_rules(ConfigRuleNames=[rule])["ConfigRules"][0]
        ),
        lambda r: r.get("ConfigRuleState") == "ACTIVE",
        timeout_s=120,
        interval_s=3.0,
        description=f"PROACTIVE rule {rule} reaches ACTIVE",
    )
    assert described["EvaluationModes"] == [{"Mode": "PROACTIVE"}], (
        f"the prerequisite rule must be enabled in PROACTIVE mode only, got "
        f"{described.get('EvaluationModes')!r}"
    )
    return rule


CHECK = "proactive-resource-evaluation-reaches-terminal-state"
GROUP = "resource-config"
SERVICES = ["config"]


# timing:real-time — workflow: 60 s https://docs.aws.amazon.com/config/latest/APIReference/API_StartResourceEvaluation.html
@tags(
    "axis:happy-path",
    "cap:c2",
    "cap:c4",
    "concern:data-plane",
    "concern:negative-classes",
    "concern:representation",
    "dp:api",
    "plane:data",
    "resource:account-singleton:config-delivery-channel",
    "resource:account-singleton:config-recorder",
    "timing:real-time",
)
def run(ctx) -> None:
    """A PROACTIVE StartResourceEvaluation mints an id, reaches a terminal status (the timeout, for a
    CUSTOM_POLICY rule), echoes its ResourceDetails and context via the summary and the filtered
    list, is idempotent per ClientToken, and refuses a changed replay (IdempotentParameterMismatch)."""
    _restore_config_recorder_on_teardown(ctx)
    cfg = ctx.client("config")
    _ensure_proactive_rule(ctx, "AWS::S3::Bucket")

    context_id = ctx.unique_name("sim2real-behav-cfg-eval-ctx-")[:128]
    resource_id = ctx.unique_name("sim2real-behav-cfg-proactive-bucket-")
    resource_details = {
        "ResourceId": resource_id,
        "ResourceType": "AWS::S3::Bucket",
        "ResourceConfiguration": json.dumps({"BucketName": resource_id}),
        "ResourceConfigurationSchemaType": "CFN_RESOURCE_SCHEMA",
    }
    # ClientToken is modelled min length 64, and 'min' IS in botocore's
    # VALIDATED_METADATA_ATTRS, so a shorter token never reaches the service --
    # the token must genuinely be >= 64 characters.
    client_token = (ctx.unique_name("sim2real-behav-cfg-token-") + "0" * 64)[:96]

    started = _retry_throttled(
        lambda: cfg.start_resource_evaluation(
            ResourceDetails=resource_details,
            EvaluationMode="PROACTIVE",
            EvaluationContext={"EvaluationContextIdentifier": context_id},
            EvaluationTimeout=60,
            ClientToken=client_token,
        )
    )
    evaluation_id = started["ResourceEvaluationId"]
    assert isinstance(evaluation_id, str) and 1 <= len(evaluation_id) <= 128, (
        f"ResourceEvaluationId must be a 1..128 character string, got {evaluation_id!r}"
    )

    # Idempotency: the same ClientToken with the same parameters must return the
    # SAME evaluation id, not launch a second evaluation.
    replay = _retry_throttled(
        lambda: cfg.start_resource_evaluation(
            ResourceDetails=resource_details,
            EvaluationMode="PROACTIVE",
            EvaluationContext={"EvaluationContextIdentifier": context_id},
            EvaluationTimeout=60,
            ClientToken=client_token,
        )
    )
    assert replay["ResourceEvaluationId"] == evaluation_id, (
        f"replaying ClientToken {client_token!r} with identical parameters must return "
        f"the original ResourceEvaluationId {evaluation_id!r}, got "
        f"{replay['ResourceEvaluationId']!r}"
    )

    # Idempotency, negative: the same ClientToken with CHANGED parameters must be
    # refused, and must not start a third evaluation.
    changed = dict(resource_details, ResourceId=resource_id + "-changed")
    code, mismatch_msg = _error(
        lambda: cfg.start_resource_evaluation(
            ResourceDetails=changed,
            EvaluationMode="PROACTIVE",
            EvaluationContext={"EvaluationContextIdentifier": context_id},
            EvaluationTimeout=60,
            ClientToken=client_token,
        )
    )
    assert code == "IdempotentParameterMismatch", (
        f"replaying ClientToken {client_token!r} with a different ResourceId must be "
        f"refused with IdempotentParameterMismatch, never silently accepted or "
        f"silently deduplicated; got {code!r}"
    )
    assert mismatch_msg == (
        f"The request inputs are not associated with the supplied client token {client_token}. "
        "You are using the same client token with one or more different parameters. "
        "Specify a new client token with the parameter changes and try again."
    ), mismatch_msg

    # Drive to a terminal state with a bounded deadline -- no bare sleep.
    summary = _poll_until(
        lambda: _retry_throttled(
            lambda: cfg.get_resource_evaluation_summary(ResourceEvaluationId=evaluation_id)
        ),
        lambda s: s.get("EvaluationStatus", {}).get("Status") in ("SUCCEEDED", "FAILED"),
        timeout_s=90,
        interval_s=5.0,
        description=f"resource evaluation {evaluation_id} reaches a terminal status",
    )
    status = summary["EvaluationStatus"]["Status"]
    # An ACTIVE CUSTOM_POLICY PROACTIVE rule scoped to this resource type
    # never actually gets invoked by on-demand StartResourceEvaluation -- the
    # evaluation idles for exactly EvaluationTimeout (60s here) and then reaches
    # FAILED, never SUCCEEDED. A target that fakes synchronous Guard evaluation
    # and returns SUCCEEDED immediately is diverging from real AWS.
    assert status == "FAILED", (
        f"a PROACTIVE evaluation of AWS::S3::Bucket against an ACTIVE CUSTOM_POLICY "
        f"PROACTIVE rule must reach FAILED (the rule is never actually invoked "
        f"on-demand) -- got {status} with FailureReason "
        f"{summary['EvaluationStatus'].get('FailureReason')!r}"
    )
    failure_reason = summary["EvaluationStatus"].get("FailureReason", "")
    assert failure_reason == "Resource evaluation timed out.", (
        f"the terminal FailureReason must be the evaluation timeout, not a "
        f"different rejection; got {failure_reason!r}"
    )
    assert summary["ResourceEvaluationId"] == evaluation_id, summary
    assert summary["EvaluationMode"] == "PROACTIVE", (
        f"the summary must echo the submitted EvaluationMode, got {summary.get('EvaluationMode')!r}"
    )
    assert summary["EvaluationContext"]["EvaluationContextIdentifier"] == context_id, summary[
        "EvaluationContext"
    ]
    echoed = summary["ResourceDetails"]
    assert echoed["ResourceId"] == resource_id, echoed
    assert echoed["ResourceType"] == "AWS::S3::Bucket", echoed
    assert json.loads(echoed["ResourceConfiguration"]) == {"BucketName": resource_id}, (
        f"the submitted ResourceConfiguration must round-trip, got "
        f"{echoed['ResourceConfiguration']!r}"
    )
    assert "EvaluationStartTimestamp" in summary, summary

    # The evaluation must be discoverable by its context, and the mismatched
    # replay must NOT have produced an extra evaluation under that context.
    listed = _poll_until(
        lambda: _retry_throttled(
            lambda: cfg.list_resource_evaluations(
                Filters={
                    "EvaluationMode": "PROACTIVE",
                    "EvaluationContextIdentifier": context_id,
                },
                Limit=100,
            )
        ),
        lambda r: len(r.get("ResourceEvaluations", [])) >= 1,
        timeout_s=120,
        interval_s=5.0,
        description=f"evaluation {evaluation_id} is listed under context {context_id}",
    )
    ids = [e["ResourceEvaluationId"] for e in listed["ResourceEvaluations"]]
    assert ids == [evaluation_id], (
        f"exactly one evaluation must exist under the unique context {context_id} -- "
        f"the idempotent replay must not have created a second; got {ids!r}"
    )
    # The list entry is a two-field summary -- ResourceEvaluationId and
    # EvaluationStartTimestamp only. It does NOT echo EvaluationMode, so the mode
    # lives entirely in the Filters vocabulary.
    entry = listed["ResourceEvaluations"][0]
    assert set(entry) == {"ResourceEvaluationId", "EvaluationStartTimestamp"}, (
        f"a ListResourceEvaluations entry carries exactly the id and the start "
        f"timestamp on real AWS; got {sorted(entry)!r}"
    )
    # ...and the Filters vocabulary is PROACTIVE-only: DETECTIVE is a modeled
    # EvaluationMode enum value that this operation refuses outright, which is what
    # proves the filter was honoured rather than ignored.
    code, msg = _error(
        lambda: cfg.list_resource_evaluations(
            Filters={
                "EvaluationMode": "DETECTIVE",
                "EvaluationContextIdentifier": context_id,
            },
            Limit=100,
        )
    )
    assert code == "InvalidParameterValueException", (
        f"ListResourceEvaluations must refuse EvaluationMode=DETECTIVE rather than "
        f"ignore the filter or return an empty page; got {code!r}"
    )
    assert msg == (
        "DETECTIVE Evaluation Mode is not supported. The supported Evaluation Modes are: [PROACTIVE]."
    ), f"the refusal must enumerate the supported modes; got {msg!r}"

    # A fabricated evaluation id must be a hard not-found, not an empty summary.
    bogus = ctx.unique_name("sim2real-behav-cfg-absent-eval-")[:128]
    code, missing_msg = _error(
        lambda: cfg.get_resource_evaluation_summary(ResourceEvaluationId=bogus)
    )
    assert code == "ResourceNotFoundException", (
        f"GetResourceEvaluationSummary on an unknown id must be "
        f"ResourceNotFoundException, never a synthesised IN_PROGRESS summary; "
        f"got {code!r}"
    )
    assert missing_msg == f"Provided ResourceEvaluationId {bogus} not found.", missing_msg


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
