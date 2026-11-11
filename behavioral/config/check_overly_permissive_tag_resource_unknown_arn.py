"""overly-permissive-tag-resource-unknown-arn."""

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


def _retry_throttled(fn, attempts=8, base_delay=2.0):
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
            )["Role"]["Arn"]
        except ClientError as exc:
            raise AssertionError(
                "no AWS Config service role exists in this account and the caller "
                "lacks iam:CreateRole, so no configuration recorder can be created: "
                f"{exc.response.get('Error', {}).get('Code')}"
            ) from exc
        ctx.on_cleanup(lambda r=created_role: iam.delete_role(RoleName=r))
        try:
            iam.attach_role_policy(RoleName=created_role, PolicyArn=_CONFIG_MANAGED_POLICY_ARN)
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
        raise AssertionError(f"could not create a configuration recorder within 120s: {last!r}")
    ctx.on_cleanup(
        lambda r=recorder: _retry_throttled(
            lambda: cfg.delete_configuration_recorder(ConfigurationRecorderName=r)
        )
    )
    return recorder, True


def _must_reject(fn, description):
    """Call fn() and return (code, message) from its ClientError. Raises if fn() succeeds instead."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"{description}: the call succeeded instead of being rejected")


CHECK = "overly-permissive-tag-resource-unknown-arn"
GROUP = "overly-permissive"
SERVICES = ["config"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """TagResource and ListTagsForResource on a config-rule ARN that does not exist fail with
    ResourceNotFoundException and its exact message, while a real rule's tag reads back before and after."""
    _restore_config_recorder_on_teardown(ctx)
    cfg = ctx.client("config")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    _ensure_recorder_exists(ctx)

    # --- Positive control: TagResource succeeds against a real config-rule ARN.
    rule_name = ctx.unique_name("sim2real-behav-cfg-rule-")
    _retry_throttled(
        lambda: cfg.put_config_rule(
            ConfigRule={
                "ConfigRuleName": rule_name,
                "Source": {"Owner": "AWS", "SourceIdentifier": "S3_BUCKET_VERSIONING_ENABLED"},
            }
        )
    )
    ctx.on_cleanup(
        lambda: _retry_throttled(lambda: cfg.delete_config_rule(ConfigRuleName=rule_name))
    )
    real_arn = _retry_throttled(lambda: cfg.describe_config_rules(ConfigRuleNames=[rule_name]))[
        "ConfigRules"
    ][0]["ConfigRuleArn"]

    cfg.tag_resource(ResourceArn=real_arn, Tags=[{"Key": "k", "Value": "v"}])
    real_tags = {
        t["Key"]: t["Value"] for t in cfg.list_tags_for_resource(ResourceArn=real_arn)["Tags"]
    }
    assert real_tags.get("k") == "v", (
        f"positive control failed: expected tag k=v on real rule {real_arn!r}, got {real_tags!r}"
    )

    # --- The negative: the SAME operation just proven to work, against a
    # syntactically valid but nonexistent config-rule ARN, must be refused.
    bogus_arn = (
        f"arn:aws:config:{ctx.region}:{account_id}:config-rule/config-rule-does-not-exist-xyz"
    )
    code, message = _must_reject(
        lambda: cfg.tag_resource(ResourceArn=bogus_arn, Tags=[{"Key": "k", "Value": "v"}]),
        "TagResource against a nonexistent config-rule ARN",
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException tagging a nonexistent config-rule ARN, "
        f"got {code!r} (message {message!r})"
    )
    not_found = f"Resource {bogus_arn} does not exist for account {account_id}"
    assert message == not_found, message

    # --- Effect absent: an independent read, a different operation than the
    # rejected mutation, still 404s -- no tag record was ever created for it.
    code, list_message = _must_reject(
        lambda: cfg.list_tags_for_resource(ResourceArn=bogus_arn),
        "ListTagsForResource on a nonexistent config-rule ARN",
    )
    assert code == "ResourceNotFoundException", (
        f"expected ListTagsForResource on the phantom ARN to also 404 with "
        f"ResourceNotFoundException, got {code!r}"
    )
    assert list_message == not_found, list_message

    # --- Terminal read at the destination: the real rule's tags are unaffected by
    # the forged call, on an independent operation from every mutating call above.
    after_tags = {
        t["Key"]: t["Value"] for t in cfg.list_tags_for_resource(ResourceArn=real_arn)["Tags"]
    }
    assert after_tags.get("k") == "v", (
        f"real rule {real_arn!r} should still carry tag k=v after the forged-ARN "
        f"call; got {after_tags!r}"
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
