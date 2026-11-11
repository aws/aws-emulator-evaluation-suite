"""put-resolver-query-log-config-policy-invalid-policy-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-resolver-query-log-config-policy-invalid-policy-rejected"
GROUP = "overly-permissive"
SERVICES = ["route53resolver"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutResolverQueryLogConfigPolicy rejects a non-JSON policy with InvalidRequestException.

    No policy is left attached (the Get call denies access), and a well-formed policy round-trips.
    """
    r53r = ctx.client("route53resolver")
    logs = ctx.client("logs")
    sts = ctx.client("sts")
    own_account_id = sts.get_caller_identity()["Account"]

    log_group_name = ctx.unique_name("/sim2real/r53r-qlc-policy-")
    logs.create_log_group(logGroupName=log_group_name)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group_name))
    log_group_arn = logs.describe_log_groups(logGroupNamePrefix=log_group_name)["logGroups"][0]["arn"]

    config = r53r.create_resolver_query_log_config(
        Name=ctx.unique_name("sim2real-qlc-"),
        DestinationArn=log_group_arn,
        CreatorRequestId=ctx.unique_name("sim2real-cr-"),
    )["ResolverQueryLogConfig"]
    config_id = config["Id"]
    config_arn = config["Arn"]
    ctx.on_cleanup(lambda: _delete_query_log_config_best_effort(r53r, config_id))

    code, message = _error(
        lambda: r53r.put_resolver_query_log_config_policy(
            Arn=config_arn, ResolverQueryLogConfigPolicy="{not valid json"
        )
    )
    assert code == "InvalidRequestException", f"code={code!r}"
    expected = (
        "[RSLVR-00312] The specified IAM policy for sharing a query logging configuration with "
        "another AWS account is invalid."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    no_policy_code, no_policy_message = _error(
        lambda: r53r.get_resolver_query_log_config_policy(Arn=config_arn)
    )
    assert no_policy_code == "AccessDeniedException", f"code={no_policy_code!r}"
    assert no_policy_message == "[RSLVR-01600] Access denied", f"message={no_policy_message!r}"

    valid_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": [own_account_id]},
                    "Action": [
                        "route53resolver:AssociateResolverQueryLogConfig",
                        "route53resolver:DisassociateResolverQueryLogConfig",
                        "route53resolver:ListResolverQueryLogConfigs",
                    ],
                    "Resource": [config_arn],
                }
            ],
        }
    )
    result = r53r.put_resolver_query_log_config_policy(
        Arn=config_arn, ResolverQueryLogConfigPolicy=valid_policy
    )
    assert result["ReturnValue"] is True, f"ReturnValue={result.get('ReturnValue')!r}"

    stored = r53r.get_resolver_query_log_config_policy(Arn=config_arn)["ResolverQueryLogConfigPolicy"]
    stored_resource = json.loads(stored)["Statement"][0]["Resource"]
    if isinstance(stored_resource, str):
        stored_resource = [stored_resource]
    assert stored_resource == [config_arn], f"sr={stored_resource!r}"


_TRACE_ID = ' Trace Id: "'


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises, with the
    per-request X-Ray trace id suffix removed. A call that succeeds raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        message = err.get("Message", "")
        head, sep, _ = message.rpartition(_TRACE_ID)
        return err.get("Code"), (head if sep and message.endswith('"') else message)
    raise AssertionError(f"expected a ClientError, the call succeeded and returned {result!r}")


def _delete_query_log_config_best_effort(r53r, config_id: str) -> None:
    try:
        r53r.delete_resolver_query_log_config(ResolverQueryLogConfigId=config_id)
    except (r53r.exceptions.ResourceNotFoundException, r53r.exceptions.InvalidRequestException):
        pass


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
