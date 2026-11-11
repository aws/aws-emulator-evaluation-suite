"""topic-rule-invalid-sql-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "topic-rule-invalid-sql-rejected"
GROUP = "e2e"
SERVICES = ["iot"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTopicRule with syntactically invalid SQL is rejected with
    SqlParseException, the broken rule never appears in the registry, and a
    syntactically valid rule in the same account still creates successfully.
    """
    iot = ctx.client("iot")
    iam = ctx.client("iam")

    role_name = ctx.unique_name("sim2real-rule-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "iot.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="publish",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "iot:Publish", "Resource": "*"}],
            }
        ),
    )
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))

    bad_rule_name = ctx.unique_name("sim2real_badsql_").replace("-", "_")
    bad_payload = {
        "sql": "SELEKT *** FROM WHERE THIS IS NOT VALID SQL !!",
        "ruleDisabled": False,
        "actions": [
            {
                "republish": {
                    "topic": "sim2real/badsql-target",
                    "roleArn": role_arn,
                }
            }
        ],
    }

    code, message = _error_code_with_retry(
        iot,
        lambda: iot.create_topic_rule(ruleName=bad_rule_name, topicRulePayload=bad_payload),
    )
    assert code == "SqlParseException", f"expected SqlParseException, got code={code!r}"
    assert message == f"Expected 'SELECT'\n\n{bad_payload['sql']}\n^ at 1:1", message

    existing_names = {r["ruleName"] for r in iot.list_topic_rules().get("rules", [])}
    assert bad_rule_name not in existing_names, "rule with invalid SQL was created despite the rejection"

    # positive control: a syntactically valid rule with the same shape succeeds.
    good_rule_name = ctx.unique_name("sim2real_goodsql_").replace("-", "_")
    good_payload = {
        "sql": "SELECT * FROM 'sim2real/badsql-source'",
        "ruleDisabled": False,
        "actions": [
            {
                "republish": {
                    "topic": "sim2real/badsql-target",
                    "roleArn": role_arn,
                }
            }
        ],
    }
    _create_topic_rule_with_retry(iot, good_rule_name, good_payload)
    ctx.on_cleanup(lambda: iot.delete_topic_rule(ruleName=good_rule_name))

    fetched = iot.get_topic_rule(ruleName=good_rule_name)
    assert fetched["rule"]["ruleName"] == good_rule_name, (
        f"expected {good_rule_name!r} readable at the destination, got {fetched['rule'].get('ruleName')!r}"
    )


def _error_code_with_retry(iot, fn, timeout_s: float = 30.0):
    """CreateTopicRule can transiently fail with InvalidRequestException
    ("unable to assume role") right after the role is created, while the new
    role propagates through IAM. Retry ONLY that transient shape; any other
    error (including a real SqlParseException) is returned immediately as
    (code, message). An unexpected success raises."""
    import time as _time
    from botocore.exceptions import ClientError

    deadline = _time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "")
            if code == "InvalidRequestException" and "unable to assume role" in message and _time.monotonic() < deadline:
                _time.sleep(3)
                continue
            return code, message
        raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _create_topic_rule_with_retry(iot, rule_name: str, payload: dict, timeout_s: float = 30.0) -> None:
    import time as _time
    from botocore.exceptions import ClientError

    deadline = _time.monotonic() + timeout_s
    while True:
        try:
            iot.create_topic_rule(ruleName=rule_name, topicRulePayload=payload)
            return
        except ClientError as exc:
            message = exc.response["Error"].get("Message", "")
            if exc.response["Error"]["Code"] == "InvalidRequestException" and "unable to assume role" in message and _time.monotonic() < deadline:
                _time.sleep(3)
                continue
            raise



def _delete_role(iam, role_name: str) -> None:
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName="publish")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
