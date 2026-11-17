"""config-rule-scope-tag-only-accepted-and-combined-update-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

_TRUST_POLICY = """{
  "Version": "2012-10-17",
  "Statement": [
    {"Effect": "Allow", "Principal": {"Service": "config.amazonaws.com"}, "Action": "sts:AssumeRole"}
  ]
}"""
_MANAGED_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
_MANAGED_SOURCE_IDENTIFIER = "S3_BUCKET_VERSIONING_ENABLED"
_SCOPE_BOTH = (
    "InvalidParameterValueException",
    "Scope cannot be applied to both resource and tag",
)


def _error(fn):
    """The ``(code, message)`` of the rejection ``fn()`` raises; raise if it succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected a rejection, but it succeeded: {result!r}")


def expect_error(fn, code, message):
    got_code, got_message = _error(fn)
    assert got_code == code, f"expected error code {code!r}, got {got_code!r} ({got_message!r})"
    assert got_message == message, f"expected message {message!r}, got {got_message!r}"


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=3.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _ensure_recorder_exists(ctx):
    """Guarantee a configuration recorder exists; reuse one already present, never start it."""
    cfg = ctx.client("config")
    if cfg.describe_configuration_recorders().get("ConfigurationRecorders", []):
        return

    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-cfg-tagscope-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_TRUST_POLICY,
        Description="sim2real behavioral fidelity probe role for AWS Config",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_MANAGED_POLICY_ARN)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_MANAGED_POLICY_ARN))

    recorder_name = ctx.unique_name("sim2real-behav-cfg-tagscope-recorder-")
    deadline = time.monotonic() + 120
    last = None
    while time.monotonic() < deadline:
        try:
            cfg.put_configuration_recorder(
                ConfigurationRecorder={
                    "name": recorder_name,
                    "roleARN": role_arn,
                    "recordingGroup": {"allSupported": False, "resourceTypes": ["AWS::S3::Bucket"]},
                }
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
    ctx.on_cleanup(lambda: cfg.delete_configuration_recorder(ConfigurationRecorderName=recorder_name))


CHECK = "config-rule-scope-tag-only-accepted-and-combined-update-rejected"
GROUP = "scope-rules"
SERVICES = ["config", "iam"]


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
    "resource:account-singleton:config-recorder",
)
def run(ctx) -> None:
    """A Scope naming only TagKey and TagValue is accepted and describes back exactly, and
    updating an existing resource-scoped rule to also carry a TagKey is refused, leaving the
    rule's own Scope exactly as it was.
    """
    cfg = ctx.client("config")
    _ensure_recorder_exists(ctx)

    # The legal neighbour: a Scope naming only TagKey and TagValue, with no resource types at all.
    tag_only_name = ctx.unique_name("sim2real-behav-cfg-tagscope-tagonly-")
    tag_key = ctx.unique_name("sim2real-behav-cfg-tagscope-key-")
    tag_value = ctx.unique_name("sim2real-behav-cfg-tagscope-value-")
    cfg.put_config_rule(
        ConfigRule={
            "ConfigRuleName": tag_only_name,
            "Source": {"Owner": "AWS", "SourceIdentifier": _MANAGED_SOURCE_IDENTIFIER},
            "Scope": {"TagKey": tag_key, "TagValue": tag_value},
        }
    )
    ctx.on_cleanup(lambda: cfg.delete_config_rule(ConfigRuleName=tag_only_name))
    tag_only_described = _poll_until(
        lambda: cfg.describe_config_rules(ConfigRuleNames=[tag_only_name])["ConfigRules"][0],
        lambda r: r.get("ConfigRuleState") == "ACTIVE",
        description=f"tag-only rule {tag_only_name} reaches ACTIVE",
    )
    assert tag_only_described["Scope"] == {"TagKey": tag_key, "TagValue": tag_value}, (
        f"a Scope created with only TagKey and TagValue must describe back exactly those two "
        f"fields, got {tag_only_described['Scope']!r}"
    )

    # An existing rule scoped only by ComplianceResourceTypes.
    resource_name = ctx.unique_name("sim2real-behav-cfg-tagscope-resource-")
    resource_types = ["AWS::S3::Bucket"]
    cfg.put_config_rule(
        ConfigRule={
            "ConfigRuleName": resource_name,
            "Source": {"Owner": "AWS", "SourceIdentifier": _MANAGED_SOURCE_IDENTIFIER},
            "Scope": {"ComplianceResourceTypes": resource_types},
        }
    )
    ctx.on_cleanup(lambda: cfg.delete_config_rule(ConfigRuleName=resource_name))
    before_update = _poll_until(
        lambda: cfg.describe_config_rules(ConfigRuleNames=[resource_name])["ConfigRules"][0],
        lambda r: r.get("ConfigRuleState") == "ACTIVE",
        description=f"resource-scoped rule {resource_name} reaches ACTIVE",
    )
    assert before_update["Scope"]["ComplianceResourceTypes"] == resource_types, before_update
    assert "TagKey" not in before_update["Scope"], before_update

    # The refused update: the same rule name, now with Scope naming BOTH ComplianceResourceTypes
    # and a TagKey, must fail without altering the existing rule.
    update_tag_key = ctx.unique_name("sim2real-behav-cfg-tagscope-updatekey-")
    expect_error(
        lambda: cfg.put_config_rule(
            ConfigRule={
                "ConfigRuleName": resource_name,
                "Source": {"Owner": "AWS", "SourceIdentifier": _MANAGED_SOURCE_IDENTIFIER},
                "Scope": {
                    "ComplianceResourceTypes": resource_types,
                    "TagKey": update_tag_key,
                },
            }
        ),
        *_SCOPE_BOTH,
    )

    after_update = cfg.describe_config_rules(ConfigRuleNames=[resource_name])["ConfigRules"][0]
    assert after_update["ConfigRuleState"] == "ACTIVE", after_update
    assert after_update["Scope"]["ComplianceResourceTypes"] == resource_types, after_update
    assert "TagKey" not in after_update["Scope"], (
        f"the refused update must not add a TagKey to the existing rule's Scope, "
        f"got {after_update['Scope']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
