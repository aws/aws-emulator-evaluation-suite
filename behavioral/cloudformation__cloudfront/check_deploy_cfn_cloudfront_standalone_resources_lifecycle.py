"""deploy-cfn-cloudfront-standalone-resources-lifecycle."""
from __future__ import annotations

import json
import time
from datetime import datetime

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-cfn-cloudfront-standalone-resources-lifecycle"
GROUP = "deploy"
SERVICES = ["cloudformation", "cloudfront"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget


def paginate(client, op, key, **kw):
    """Every item under ``key`` across all pages of ``op``; presence and absence read every page.

    A ``key`` the operation's output does not declare fails instead of reading as [].
    """
    model = client.meta.service_model.operation_model(client.meta.method_to_api_mapping[op])
    assert key in model.output_shape.members, f"{op} output has no member {key!r}"
    return [x for page in client.get_paginator(op).paginate(**kw) for x in page.get(key, [])]


def wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=300.0):
    """Poll DescribeStacks by StackId every 2 s until a status in ``terminal``; return it.

    Every error propagates: no ClientError ever stands for "done" or "gone".
    """
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def delete_stack(cf, stack_id):
    """Delete by StackId within one deadline; raise unless DELETE_COMPLETE. Safe to call twice.

    A stack still creating or updating is first waited out; a failure names each resource's reason.
    """
    deadline = time.monotonic() + _DELETE_BUDGET_S
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status not in ("DELETE_IN_PROGRESS",
                                                          "REVIEW_IN_PROGRESS"):
        wait_stack(cf, stack_id, _TERMINAL, deadline - time.monotonic())
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"},
                        deadline - time.monotonic())
    if status != "DELETE_COMPLETE":
        events = stack_events(cf, stack_id)
        starts = [i for i, e in enumerate(events) if e.get("PhysicalResourceId") == stack_id
                  and e["ResourceStatus"] == "DELETE_IN_PROGRESS"]
        failed = [(e["LogicalResourceId"], e.get("ResourceStatusReason"))
                  for e in events[starts[-1] if starts else 0:]
                  if e["ResourceStatus"] == "DELETE_FAILED"]
        raise AssertionError(f"stack {stack_id} delete ended {status!r}: {failed!r}")


def delete_stack_named(cf, name, stack_id=None):
    """delete_stack by ``stack_id``, else by the StackId DescribeStacks(StackName=name) returns.

    A ``name`` CloudFormation never accepted ("does not exist") is nothing to delete; the
    client's own ``ClientError`` keeps the helper free of imports.
    """
    if stack_id is None:
        try:
            stack_id = cf.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
        except cf.exceptions.ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) == (
                    "ValidationError", f"Stack with id {name} does not exist"):
                return
            raise
    delete_stack(cf, stack_id)


def create_stack(ctx, cf, name, template, **kw):
    """CreateStack tagged sim2real=<name> (propagates to every taggable resource); cleanup first.

    ``name`` comes from ctx.unique_name("sim2real-..."), so the tag value is unique per run. The
    cleanup is registered before the call: a stack AWS accepted is deleted even if the call raises.
    """
    created = {}
    ctx.on_cleanup(lambda: delete_stack_named(cf, name, created.get("StackId")))
    created["StackId"] = cf.create_stack(
        StackName=name, TemplateBody=template, Tags=[{"Key": "sim2real", "Value": name}], **kw
    )["StackId"]
    return created["StackId"]


def stack_outputs(cf, stack_id):
    """The stack's Outputs as {OutputKey: OutputValue}."""
    stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    return paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]


def decisive_rows(events, *logical_ids):
    """``(logical id, status)`` of each non-IN_PROGRESS row, oldest first (subsequence asserts)."""
    return [
        (e["LogicalResourceId"], e["ResourceStatus"]) for e in events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
        and (not logical_ids or e["LogicalResourceId"] in logical_ids)
    ]


def expect_error(fn, code, message, undo=None):
    """Assert ``fn()`` raises exactly ``(code, message)``.

    On an unexpected success ``undo(result)`` registers the cleanup before the failure is raised.
    """
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    if undo is not None:
        undo(result)
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


# ---- Check-specific: the template, then run(). ----

_CP_PARAMETERS = {
    "CookiesConfig": {"CookieBehavior": "none"},
    "HeadersConfig": {"HeaderBehavior": "none"},
    "QueryStringsConfig": {"QueryStringBehavior": "none"},
    "EnableAcceptEncodingGzip": False,
    "EnableAcceptEncodingBrotli": False,
}
_FN_CODE = """function handler(event) {
    return event;
}
"""


def _template(names: dict) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Oac": {
                    "Type": "AWS::CloudFront::OriginAccessControl",
                    "Properties": {
                        "OriginAccessControlConfig": {
                            "Name": names["oac"],
                            "OriginAccessControlOriginType": "s3",
                            "SigningBehavior": "always",
                            "SigningProtocol": "sigv4",
                        }
                    },
                },
                "CachePolicy": {
                    "Type": "AWS::CloudFront::CachePolicy",
                    "Properties": {
                        "CachePolicyConfig": {
                            "Name": names["cache_policy"],
                            "MinTTL": 1,
                            "DefaultTTL": 50,
                            "MaxTTL": 100,
                            "ParametersInCacheKeyAndForwardedToOrigin": _CP_PARAMETERS,
                        }
                    },
                },
                "Oai": {
                    "Type": "AWS::CloudFront::CloudFrontOriginAccessIdentity",
                    "Properties": {
                        "CloudFrontOriginAccessIdentityConfig": {"Comment": names["oai_comment"]}
                    },
                },
                "OriginRequestPolicy": {
                    "Type": "AWS::CloudFront::OriginRequestPolicy",
                    "Properties": {
                        "OriginRequestPolicyConfig": {
                            "Name": names["origin_request_policy"],
                            "HeadersConfig": {"HeaderBehavior": "none"},
                            "CookiesConfig": {"CookieBehavior": "none"},
                            "QueryStringsConfig": {"QueryStringBehavior": "none"},
                        }
                    },
                },
                "ResponseHeadersPolicy": {
                    "Type": "AWS::CloudFront::ResponseHeadersPolicy",
                    "Properties": {
                        "ResponseHeadersPolicyConfig": {
                            "Name": names["response_headers_policy"],
                            "SecurityHeadersConfig": {
                                "FrameOptions": {"FrameOption": "DENY", "Override": True}
                            },
                        }
                    },
                },
                "Kvs": {
                    "Type": "AWS::CloudFront::KeyValueStore",
                    "Properties": {"Name": names["kvs"], "Comment": names["kvs_comment"]},
                },
                "ConnFn": {
                    "Type": "AWS::CloudFront::ConnectionFunction",
                    "Properties": {
                        "Name": names["connection_function"],
                        "ConnectionFunctionCode": _FN_CODE,
                        "ConnectionFunctionConfig": {
                            "Comment": names["connection_function_comment"],
                            "Runtime": "cloudfront-js-2.0",
                        },
                        "AutoPublish": False,
                    },
                },
            },
            "Outputs": {
                "OacId": {"Value": {"Ref": "Oac"}},
                "CachePolicyId": {"Value": {"Ref": "CachePolicy"}},
                "CachePolicyLastModified": {"Value": {"Fn::GetAtt": ["CachePolicy", "LastModifiedTime"]}},
                "OaiId": {"Value": {"Ref": "Oai"}},
                "OaiS3CanonicalUserId": {"Value": {"Fn::GetAtt": ["Oai", "S3CanonicalUserId"]}},
                "OriginRequestPolicyId": {"Value": {"Ref": "OriginRequestPolicy"}},
                "OriginRequestPolicyLastModified": {
                    "Value": {"Fn::GetAtt": ["OriginRequestPolicy", "LastModifiedTime"]}
                },
                "ResponseHeadersPolicyId": {"Value": {"Ref": "ResponseHeadersPolicy"}},
                "ResponseHeadersPolicyLastModified": {
                    "Value": {"Fn::GetAtt": ["ResponseHeadersPolicy", "LastModifiedTime"]}
                },
                "KvsName": {"Value": {"Ref": "Kvs"}},
                "KvsArn": {"Value": {"Fn::GetAtt": ["Kvs", "Arn"]}},
                "KvsId": {"Value": {"Fn::GetAtt": ["Kvs", "Id"]}},
                "KvsStatus": {"Value": {"Fn::GetAtt": ["Kvs", "Status"]}},
                "ConnFnId": {"Value": {"Ref": "ConnFn"}},
                "ConnFnArn": {"Value": {"Fn::GetAtt": ["ConnFn", "ConnectionFunctionArn"]}},
                "ConnFnStage": {"Value": {"Fn::GetAtt": ["ConnFn", "Stage"]}},
                "ConnFnStatus": {"Value": {"Fn::GetAtt": ["ConnFn", "Status"]}},
            },
        }
    )


def _parse_ts(value: str) -> datetime:
    """A CloudFormation Output's ISO-8601 timestamp as a timezone-aware datetime."""
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _cf_items(call, list_key, **kw):
    """Every ``Items`` entry of a CloudFront Marker-paged list, across every page."""
    items, marker = [], None
    while True:
        page = call(**kw, **({"Marker": marker} if marker else {}))[list_key]
        items += page.get("Items", [])
        marker = page.get("NextMarker")
        if not marker:
            return items


def _one(items, what):
    assert len(items) == 1, f"expected one listed {what}, got {items!r}"
    return items[0]


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Seven CloudFormation CloudFront policy, identity, store and function resources read back.

    Each Ref matches its CloudFront list entry found by name or comment, every templated property
    and GetAtt matches CloudFront, and deleting the stack removes every one of them.
    """
    cfn = ctx.client("cloudformation")
    cf = ctx.client("cloudfront")
    names = {
        "oac": ctx.unique_name("sim2real-cfnswp-oac-"),
        "cache_policy": ctx.unique_name("sim2real-cfnswp-cp-"),
        "oai_comment": ctx.unique_name("sim2real-cfnswp-oai-"),
        "origin_request_policy": ctx.unique_name("sim2real-cfnswp-orp-"),
        "response_headers_policy": ctx.unique_name("sim2real-cfnswp-rhp-"),
        "kvs": ctx.unique_name("sim2real-cfnswp-kvs-"),
        "kvs_comment": ctx.unique_name("sim2real-cfnswp-kvsc-"),
        "connection_function": ctx.unique_name("sim2real-cfnswp-cfn-"),
        "connection_function_comment": ctx.unique_name("sim2real-cfnswp-cfnc-"),
    }
    stack_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-cfnswp-stack-"), _template(names))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)

    oac = _one([o for o in _cf_items(cf.list_origin_access_controls, "OriginAccessControlList")
                if o["Name"] == names["oac"]], "origin access control")
    assert oac["Id"] == out["OacId"], f"listed OAC Id {oac['Id']!r} != Ref {out['OacId']!r}"
    oac_cfg = cf.get_origin_access_control(Id=oac["Id"])["OriginAccessControl"][
        "OriginAccessControlConfig"]
    want = {"Name": names["oac"], "OriginAccessControlOriginType": "s3", "SigningBehavior": "always",
            "SigningProtocol": "sigv4"}
    assert {k: oac_cfg.get(k) for k in want} == want, f"OAC config {oac_cfg!r}"

    cp = _one([i["CachePolicy"]
               for i in _cf_items(cf.list_cache_policies, "CachePolicyList", Type="custom")
               if i["CachePolicy"]["CachePolicyConfig"]["Name"] == names["cache_policy"]],
              "cache policy")
    assert cp["Id"] == out["CachePolicyId"], f"listed CachePolicy Id {cp['Id']!r} != Ref"
    assert cp["LastModifiedTime"] == _parse_ts(out["CachePolicyLastModified"]), (
        f"CachePolicy LastModifiedTime {cp['LastModifiedTime']!r} != GetAtt "
        f"{out['CachePolicyLastModified']!r}"
    )
    cp_cfg = cf.get_cache_policy(Id=cp["Id"])["CachePolicy"]["CachePolicyConfig"]
    want = {"Name": names["cache_policy"], "MinTTL": 1, "DefaultTTL": 50, "MaxTTL": 100,
            "ParametersInCacheKeyAndForwardedToOrigin": _CP_PARAMETERS}
    assert {k: cp_cfg.get(k) for k in want} == want, f"CachePolicy config {cp_cfg!r}"

    oai = _one([o for o in _cf_items(cf.list_cloud_front_origin_access_identities,
                                     "CloudFrontOriginAccessIdentityList")
                if o["Comment"] == names["oai_comment"]], "origin access identity")
    assert (oai["Id"], oai["S3CanonicalUserId"]) == (out["OaiId"], out["OaiS3CanonicalUserId"]), (
        f"listed OAI {oai!r}; Ref {out['OaiId']!r}, GetAtt {out['OaiS3CanonicalUserId']!r}"
    )

    orp = _one([i["OriginRequestPolicy"] for i in _cf_items(
        cf.list_origin_request_policies, "OriginRequestPolicyList", Type="custom")
        if i["OriginRequestPolicy"]["OriginRequestPolicyConfig"]["Name"]
        == names["origin_request_policy"]], "origin request policy")
    assert orp["Id"] == out["OriginRequestPolicyId"], f"listed OriginRequestPolicy Id {orp['Id']!r}"
    assert orp["LastModifiedTime"] == _parse_ts(out["OriginRequestPolicyLastModified"]), (
        f"OriginRequestPolicy LastModifiedTime {orp['LastModifiedTime']!r}"
    )
    orp_cfg = orp["OriginRequestPolicyConfig"]
    got = (orp_cfg["HeadersConfig"]["HeaderBehavior"], orp_cfg["CookiesConfig"]["CookieBehavior"],
           orp_cfg["QueryStringsConfig"]["QueryStringBehavior"])
    assert got == ("none", "none", "none"), f"OriginRequestPolicy behaviors {got!r}"

    rhp = _one([i["ResponseHeadersPolicy"] for i in _cf_items(
        cf.list_response_headers_policies, "ResponseHeadersPolicyList", Type="custom")
        if i["ResponseHeadersPolicy"]["ResponseHeadersPolicyConfig"]["Name"]
        == names["response_headers_policy"]], "response headers policy")
    assert rhp["Id"] == out["ResponseHeadersPolicyId"], (
        f"listed ResponseHeadersPolicy Id {rhp['Id']!r}"
    )
    assert rhp["LastModifiedTime"] == _parse_ts(out["ResponseHeadersPolicyLastModified"]), (
        f"ResponseHeadersPolicy LastModifiedTime {rhp['LastModifiedTime']!r}"
    )
    frame = rhp["ResponseHeadersPolicyConfig"]["SecurityHeadersConfig"]["FrameOptions"]
    assert frame == {"FrameOption": "DENY", "Override": True}, f"FrameOptions {frame!r}"

    kvs = _one([k for k in _cf_items(cf.list_key_value_stores, "KeyValueStoreList")
                if k["Name"] == names["kvs"]], "key value store")
    # ListKeyValueStores omits Comment: the comment is read through DescribeKeyValueStore.
    described = cf.describe_key_value_store(Name=kvs["Name"])["KeyValueStore"]
    got = (kvs["Name"], kvs["Id"], kvs["ARN"], kvs["Status"], described["ARN"],
           described.get("Comment"))
    want = (out["KvsName"], out["KvsId"], out["KvsArn"], out["KvsStatus"], out["KvsArn"],
            names["kvs_comment"])
    assert got == want, f"listed and described KeyValueStore {got!r}, expected {want!r}"

    conn = _one([c for c in paginate(cf, "list_connection_functions", "ConnectionFunctions")
                 if c["Name"] == names["connection_function"]], "connection function")
    # ListConnectionFunctions omits Status: Status and the config are read through
    # DescribeConnectionFunction (its ARN and Stage == the listing's and the GetAtts too).
    summary = cf.describe_connection_function(Identifier=conn["Id"])["ConnectionFunctionSummary"]
    config = summary.get("ConnectionFunctionConfig", {})
    got = (conn["Id"], conn["ConnectionFunctionArn"], conn["Stage"],
           summary.get("ConnectionFunctionArn"), summary.get("Stage"), summary.get("Status"),
           config.get("Comment"), config.get("Runtime"))
    want = (out["ConnFnId"], out["ConnFnArn"], out["ConnFnStage"], out["ConnFnArn"],
            out["ConnFnStage"], out["ConnFnStatus"], names["connection_function_comment"],
            "cloudfront-js-2.0")
    assert got == want, f"listed and described ConnectionFunction {got!r}, expected {want!r}"
    # AutoPublish False: the function stays in DEVELOPMENT, and the GetAtt says so too.
    assert (conn["Stage"], out["ConnFnStage"]) == ("DEVELOPMENT", "DEVELOPMENT"), (
        f"ConnectionFunction Stage {conn['Stage']!r}, GetAtt {out['ConnFnStage']!r}"
    )
    code = cf.get_connection_function(Identifier=conn["Id"])["ConnectionFunctionCode"].read()
    assert code.decode() == _FN_CODE, f"ConnectionFunction code differs: {code!r}"

    delete_stack(cfn, stack_id)
    gone = (
        (lambda: cf.get_origin_access_control(Id=out["OacId"]),
         ("NoSuchOriginAccessControl", "The specified origin access control does not exist.")),
        (lambda: cf.get_cache_policy(Id=out["CachePolicyId"]),
         ("NoSuchCachePolicy", "The specified cache policy does not exist.")),
        (lambda: cf.get_cloud_front_origin_access_identity(Id=out["OaiId"]),
         ("NoSuchCloudFrontOriginAccessIdentity",
          "The specified CloudFront origin access identity does not exist.")),
        (lambda: cf.get_origin_request_policy(Id=out["OriginRequestPolicyId"]),
         ("NoSuchOriginRequestPolicy", "The specified origin request policy does not exist.")),
        (lambda: cf.get_response_headers_policy(Id=out["ResponseHeadersPolicyId"]),
         ("NoSuchResponseHeadersPolicy", "The specified response headers policy does not exist.")),
        (lambda: cf.describe_key_value_store(Name=out["KvsName"]),
         ("EntityNotFound", "The specified KeyValueStore does not exist.")),
        (lambda: cf.describe_connection_function(Identifier=out["ConnFnId"]),
         ("EntityNotFound", "The specified connection function does not exist.")),
    )
    for read, not_found in gone:
        expect_error(read, *not_found)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
