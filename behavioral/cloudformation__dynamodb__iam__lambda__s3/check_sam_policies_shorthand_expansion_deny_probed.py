"""sam-policies-shorthand-expansion-deny-probed."""

from __future__ import annotations

import base64
import json
import time
import uuid
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sam-policies-shorthand-expansion-deny-probed"

GROUP = "deploy-sam-transform"

SERVICES = ["cloudformation", "dynamodb", "iam", "lambda", "s3"]

# The exact documents the SAM transform emits for these two shorthand names (as in
# aws-sam-translator==1.113.0). Set equality on these is the whole point of the check.
_S3_READ_ACTIONS = frozenset({
    "s3:GetObject",
    "s3:ListBucket",
    "s3:GetBucketLocation",
    "s3:GetObjectVersion",
    "s3:GetLifecycleConfiguration",
})
_DDB_CRUD_ACTIONS = frozenset({
    "dynamodb:GetItem",
    "dynamodb:DeleteItem",
    "dynamodb:PutItem",
    "dynamodb:Scan",
    "dynamodb:Query",
    "dynamodb:UpdateItem",
    "dynamodb:BatchWriteItem",
    "dynamodb:BatchGetItem",
    "dynamodb:DescribeTable",
    "dynamodb:ConditionCheckItem",
})

_MANAGED_BASIC = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
_MANAGED_DDB_STREAM = "arn:aws:iam::aws:policy/service-role/AWSLambdaDynamoDBExecutionRole"

# A generic probe: it performs exactly one boto3 call under the SYNTHESIZED role's own
# credentials and reports the outcome. The denial has to be observed by the role, not by the
# check's admin credentials, or the deny arm proves nothing.
_PROBE_CODE = (
    "import base64, json\n"
    "import boto3\n"
    "def handler(event, context):\n"
    "    svc, call = event['op'].split('.', 1)\n"
    "    try:\n"
    "        r = getattr(boto3.client(svc), call)(**event.get('args', {}))\n"
    "    except Exception as exc:\n"
    "        resp = getattr(exc, 'response', None) or {}\n"
    "        return {'ok': False, 'code': resp.get('Error', {}).get('Code'),\n"
    "                'message': str(exc)[:300]}\n"
    "    if 'Body' in r:\n"
    "        r['Body'] = base64.b64encode(r['Body'].read()).decode()\n"
    "    r.pop('ResponseMetadata', None)\n"
    "    return {'ok': True, 'result': json.loads(json.dumps(r, default=str))}\n"
)

_NOOP_CODE = "def handler(event, context):\n    return 'ok'\n"


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes",
      "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """SAM `Policies` shorthand expands into the exact IAM documents the templates define (S3ReadPolicy,
    DynamoDBCrudPolicy, positional inline names, Events-derived managed policies), proven by calls the
    role may make AND deny probes it must fail, so an `Action: "*"` expansion cannot pass.
    """
    cfn = ctx.client("cloudformation")
    iam = ctx.client("iam")
    awslambda = ctx.client("lambda")
    s3 = ctx.client("s3")
    ddb = ctx.client("dynamodb")

    bucket = _xname(ctx, "sam-assets")
    items_table = _xname(ctx, "sam-items")
    decoy_table = _xname(ctx, "sam-decoy")
    probe_fn = _xname(ctx, "sam-probe")
    streamer_fn = _xname(ctx, "sam-streamer")
    seed_key = "seed/probe.txt"
    seed_body = f"sim2real-seed-{uuid.uuid4().hex}".encode()

    # Registered BEFORE the deploy so LIFO runs them AFTER the stack delete: belt-and-braces
    # sweeps for the case where the stack delete leaves a table or a log group behind. Lambda
    # creates /aws/lambda/<name> on first invocation and CloudFormation never owns it.
    ctx.on_cleanup(lambda: _delete_table_if_present(ddb, items_table))
    ctx.on_cleanup(lambda: _delete_table_if_present(ddb, decoy_table))
    for fn_name in (probe_fn, streamer_fn):
        ctx.on_cleanup(
            lambda n=fn_name: _delete_log_group_if_present(ctx, f"/aws/lambda/{n}")
        )

    template = json.dumps(_template(bucket, items_table, decoy_table, probe_fn, streamer_fn))

    change_set = _create_change_set(ctx, template)
    assert change_set["Status"] == "CREATE_COMPLETE", (
        "the SAM transform rejected a valid document: "
        f"{change_set['Status']!r} / {change_set.get('StatusReason')!r}"
    )
    synthesized = sorted(
        c["ResourceChange"]["LogicalResourceId"] for c in change_set.get("Changes", [])
    )
    # The transform runs at change-set time, so the synthesized roles are visible BEFORE
    # anything exists. An emulator that invents them at create time fails here.
    assert synthesized == [
        "Assets", "Decoy", "Items", "Probe", "ProbeRole", "Streamer", "StreamerDdb",
        "StreamerRole",
    ], f"change set does not carry the transform-expanded resource set; got {synthesized!r}"

    stack_name = change_set["stack_name"]
    _execute_change_set(ctx, stack_name, change_set["change_set_name"])

    resources = _stack_resources(cfn, stack_name)
    probe_role = resources["ProbeRole"][1]
    streamer_role = resources["StreamerRole"][1]

    # ---- the synthesized documents, read straight out of IAM ------------------------------
    policy_names = sorted(
        name
        for page in iam.get_paginator("list_role_policies").paginate(RoleName=probe_role)
        for name in page["PolicyNames"]
    )
    assert policy_names == ["ProbeRolePolicy0", "ProbeRolePolicy1"], (
        "SAM names one inline policy per Policies entry, positionally and in declaration "
        f"order; got {policy_names!r}"
    )

    doc0 = iam.get_role_policy(RoleName=probe_role, PolicyName="ProbeRolePolicy0")[
        "PolicyDocument"
    ]
    stmts0 = doc0["Statement"]
    assert len(stmts0) == 1, f"S3ReadPolicy expands to one statement; got {stmts0!r}"
    actions0 = frozenset(_as_list(stmts0[0]["Action"]))
    assert actions0 == _S3_READ_ACTIONS, (
        "S3ReadPolicy must expand to exactly those five read actions -- an over-broad "
        f"expansion is the defect this asserts against. Got {sorted(actions0)!r}"
    )
    assert frozenset(_as_list(stmts0[0]["Resource"])) == frozenset({
        f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*",
    }), (
        "S3ReadPolicy's two Fn::Sub ARNs (bucket and object form) must be resolved to the real "
        f"bucket; got {stmts0[0]['Resource']!r}"
    )

    doc1 = iam.get_role_policy(RoleName=probe_role, PolicyName="ProbeRolePolicy1")[
        "PolicyDocument"
    ]
    stmts1 = doc1["Statement"]
    assert len(stmts1) == 1, f"DynamoDBCrudPolicy expands to one statement; got {stmts1!r}"
    actions1 = frozenset(_as_list(stmts1[0]["Action"]))
    assert actions1 == _DDB_CRUD_ACTIONS, (
        "DynamoDBCrudPolicy must expand to exactly those ten actions; it grants neither "
        f"DeleteTable nor ListTables. Got {sorted(actions1)!r}"
    )
    ddb_arn = f"arn:aws:dynamodb:{ctx.region}:{_account_id(ctx)}:table/{items_table}"
    assert frozenset(_as_list(stmts1[0]["Resource"])) == frozenset({
        ddb_arn, f"{ddb_arn}/index/*",
    }), (
        "DynamoDBCrudPolicy must be scoped to the named table and its indexes only; got "
        f"{stmts1[0]['Resource']!r}"
    )

    role_tags = {t["Key"]: t["Value"] for t in iam.get_role(RoleName=probe_role)["Role"].get("Tags", [])}
    assert role_tags.get("lambda:createdBy") == "SAM", (
        f"the transform tags every role it synthesizes; tags were {role_tags!r}"
    )

    # ---- ManagedPolicyArns is derived from the declared Events, not a fixed list ----------
    assert _attached(iam, probe_role) == [_MANAGED_BASIC], (
        "the events-free function's role must carry only the basic execution role; got "
        f"{_attached(iam, probe_role)!r}"
    )
    assert _attached(iam, streamer_role) == sorted([_MANAGED_BASIC, _MANAGED_DDB_STREAM]), (
        "one DynamoDB-stream Event must add AWSLambdaDynamoDBExecutionRole and nothing else -- "
        f"the managed set is derived from the event types. Got {_attached(iam, streamer_role)!r}"
    )

    # ---- seed the estate with the check's own (admin) credentials --------------------------
    s3.put_object(Bucket=bucket, Key=seed_key, Body=seed_body)
    ctx.on_cleanup(lambda: _empty_bucket_if_present(s3, bucket))

    # ---- allow probes: the grant is real, and the CONTENT is checked -----------------------
    got = _probe_ok(awslambda, probe_fn, "s3.get_object", Bucket=bucket, Key=seed_key)
    assert base64.b64decode(got["Body"]) == seed_body, (
        f"s3:GetObject under the synthesized role returned {got.get('Body')!r}, not the seeded bytes"
    )
    listed = _probe_ok(awslambda, probe_fn, "s3.list_objects_v2", Bucket=bucket)
    assert [o["Key"] for o in listed.get("Contents", [])] == [seed_key], (
        f"s3:ListBucket under the synthesized role listed {listed.get('Contents')!r}"
    )
    described = _probe_ok(awslambda, probe_fn, "dynamodb.describe_table", TableName=items_table)
    assert described["Table"]["TableName"] == items_table, (
        f"dynamodb:DescribeTable returned {described['Table'].get('TableName')!r}"
    )
    nonce = uuid.uuid4().hex
    _probe_ok(awslambda, probe_fn, "dynamodb.put_item", TableName=items_table,
              Item={"pk": {"S": nonce}, "v": {"S": nonce}})
    read_back = _probe_ok(awslambda, probe_fn, "dynamodb.get_item", TableName=items_table,
                          Key={"pk": {"S": nonce}}, ConsistentRead=True)
    assert read_back.get("Item") == {"pk": {"S": nonce}, "v": {"S": nonce}}, (
        f"the PutItem the role was granted did not round-trip; GetItem gave {read_back!r}"
    )
    queried = _probe_ok(awslambda, probe_fn, "dynamodb.query", TableName=items_table,
                        KeyConditionExpression="pk = :p",
                        ExpressionAttributeValues={":p": {"S": nonce}})
    assert queried["Count"] == 1, f"dynamodb:Query returned Count {queried.get('Count')!r}, not 1"

    # ---- deny probes: each is an action the expanded document must NOT grant ---------------
    assert _probe_denied(awslambda, probe_fn, "s3.put_object", Bucket=bucket,
                         Key="denied/x", Body="x") == "AccessDenied", (
        "S3ReadPolicy must not grant s3:PutObject"
    )
    assert _probe_denied(awslambda, probe_fn, "s3.delete_object", Bucket=bucket,
                         Key=seed_key) == "AccessDenied", (
        "S3ReadPolicy must not grant s3:DeleteObject"
    )
    assert _probe_denied(awslambda, probe_fn, "dynamodb.delete_table",
                         TableName=items_table) == "AccessDeniedException", (
        "DynamoDBCrudPolicy must not grant dynamodb:DeleteTable"
    )
    assert _probe_denied(awslambda, probe_fn,
                         "dynamodb.list_tables") == "AccessDeniedException", (
        "DynamoDBCrudPolicy must not grant dynamodb:ListTables"
    )
    assert _probe_denied(awslambda, probe_fn, "dynamodb.put_item", TableName=decoy_table,
                         Item={"pk": {"S": nonce}}) == "AccessDeniedException", (
        "the expansion must be scoped to the named table -- a PutItem on the decoy table in the "
        "same stack proves the Resource was not table/*"
    )

    # ---- effect-absent: the denials were real, not cosmetic --------------------------------
    assert _error_code(lambda: s3.head_object(Bucket=bucket, Key="denied/x")) == "404", (
        "the denied s3:PutObject must have created nothing; HeadObject found the object"
    )
    assert "Item" not in ddb.get_item(TableName=decoy_table, Key={"pk": {"S": nonce}},
                                      ConsistentRead=True), (
        "the denied PutItem on the decoy table must have written nothing"
    )

    # ---- control: the allowed call still works, so the denials are action-specific ---------
    control = _probe_ok(awslambda, probe_fn, "s3.get_object", Bucket=bucket, Key=seed_key)
    assert base64.b64decode(control["Body"]) == seed_body, (
        "the control s3:GetObject after the deny probes must still return the seeded bytes; "
        f"got {control.get('Body')!r}"
    )

    # ---- failure arm, really injected: take ONE expanded document away --------------------
    iam.delete_role_policy(RoleName=probe_role, PolicyName="ProbeRolePolicy1")
    flipped = _poll_until(
        lambda: _probe(awslambda, probe_fn, "dynamodb.put_item", TableName=items_table,
                       Item={"pk": {"S": "after-" + uuid.uuid4().hex}}),
        lambda r: r.get("ok") is False,
        timeout_s=180.0,
        interval_s=3.0,
        description="PutItem denied after ProbeRolePolicy1 was deleted",
    )
    assert flipped.get("code") == "AccessDeniedException", (
        "with the DynamoDBCrudPolicy expansion deleted, PutItem must be denied with "
        f"AccessDeniedException; got {flipped!r}"
    )
    still_allowed = _probe_ok(awslambda, probe_fn, "s3.get_object", Bucket=bucket, Key=seed_key)
    assert base64.b64decode(still_allowed["Body"]) == seed_body, (
        "deleting ProbeRolePolicy1 must not affect ProbeRolePolicy0's grant; the control "
        f"s3:GetObject returned {still_allowed.get('Body')!r}"
    )

    # ---- restore: the identical call succeeds again once the deleted document returns -----
    iam.put_role_policy(
        RoleName=probe_role, PolicyName="ProbeRolePolicy1", PolicyDocument=json.dumps(doc1)
    )
    restored_key = "restored-" + uuid.uuid4().hex
    restored = _poll_until(
        lambda: _probe(awslambda, probe_fn, "dynamodb.put_item", TableName=items_table,
                       Item={"pk": {"S": restored_key}}),
        lambda r: r.get("ok") is True,
        timeout_s=180.0,
        interval_s=3.0,
        description="PutItem allowed again after ProbeRolePolicy1 was restored",
    )
    assert restored.get("ok") is True, (
        f"restoring ProbeRolePolicy1 with its original document must re-permit PutItem; got "
        f"{restored!r}"
    )
    restored_read = ddb.get_item(TableName=items_table, Key={"pk": {"S": restored_key}},
                                  ConsistentRead=True)
    assert restored_read.get("Item") == {"pk": {"S": restored_key}}, (
        "the write the restored policy re-permitted did not round-trip; GetItem gave "
        f"{restored_read!r}"
    )


# --------------------------------------------------------------------------------------- #

_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": _MANAGED_TAG_KEY, "Value": "true"},
            {"Key": "sim2real:prefix", "Value": _XSVC_PREFIX.rstrip("-")}]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _as_list(v) -> list:
    return v if isinstance(v, list) else [v]


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _template(bucket, items_table, decoy_table, probe_fn, streamer_fn) -> dict:
    """A SAM template whose ONLY IAM is two shorthand policy names plus one Event."""
    return {
        "Transform": "AWS::Serverless-2016-10-31",
        "Resources": {
            "Assets": {"Type": "AWS::S3::Bucket", "Properties": {"BucketName": bucket}},
            "Items": {"Type": "AWS::DynamoDB::Table", "Properties": {
                "TableName": items_table, "BillingMode": "PAY_PER_REQUEST",
                "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
                "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
                "StreamSpecification": {"StreamViewType": "NEW_AND_OLD_IMAGES"}}},
            "Decoy": {"Type": "AWS::DynamoDB::Table", "Properties": {
                "TableName": decoy_table, "BillingMode": "PAY_PER_REQUEST",
                "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
                "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}]}},
            # No Events at all: its managed set must collapse to the basic execution role, and
            # nothing but the two shorthand names may grant it anything.
            "Probe": {"Type": "AWS::Serverless::Function", "Properties": {
                "FunctionName": probe_fn, "Handler": "index.handler",
                "Runtime": "python3.12", "Timeout": 30, "InlineCode": _PROBE_CODE,
                "Policies": [{"S3ReadPolicy": {"BucketName": {"Ref": "Assets"}}},
                             {"DynamoDBCrudPolicy": {"TableName": {"Ref": "Items"}}}]}},
            # The one-variable-changed sibling: identical except for a single DynamoDB event.
            "Streamer": {"Type": "AWS::Serverless::Function", "Properties": {
                "FunctionName": streamer_fn, "Handler": "index.handler",
                "Runtime": "python3.12", "InlineCode": _NOOP_CODE,
                "Events": {"Ddb": {"Type": "DynamoDB", "Properties": {
                    "Stream": {"Fn::GetAtt": ["Items", "StreamArn"]},
                    "StartingPosition": "LATEST", "BatchSize": 5}}}}},
        },
    }


def _attached(iam, role_name: str) -> list[str]:
    """Every attached managed-policy ARN, paginated: page one is not the set."""
    return sorted(
        p["PolicyArn"]
        for page in iam.get_paginator("list_attached_role_policies").paginate(RoleName=role_name)
        for p in page["AttachedPolicies"]
    )


def _stack_resources(cfn, stack_name: str) -> dict[str, tuple[str, str]]:
    """{logical id: (type, physical id)} for every resource in the stack, paginated."""
    out: dict[str, tuple[str, str]] = {}
    for page in cfn.get_paginator("list_stack_resources").paginate(StackName=stack_name):
        for r in page["StackResourceSummaries"]:
            out[r["LogicalResourceId"]] = (r["ResourceType"], r["PhysicalResourceId"])
    return out


def _probe(awslambda, function_name: str, op: str, **args) -> dict:
    """Run one boto3 call inside the function, i.e. under the SYNTHESIZED role's credentials."""
    response = awslambda.invoke(
        FunctionName=function_name,
        InvocationType="RequestResponse",
        Payload=json.dumps({"op": op, "args": args}).encode(),
    )
    body = response["Payload"].read().decode()
    assert not response.get("FunctionError"), f"probe {op} crashed: {body[:400]}"
    return json.loads(body)


def _probe_ok(awslambda, function_name: str, op: str, **args) -> dict:
    r = _probe(awslambda, function_name, op, **args)
    assert r.get("ok") is True, (
        f"the synthesized role must be allowed to {op}; the probe reported {r!r}"
    )
    return r["result"]


def _probe_denied(awslambda, function_name: str, op: str, **args) -> str:
    """The error code the role saw. Raises when the call unexpectedly SUCCEEDED.

    Returning a falsy sentinel there would turn the strongest possible signal -- an
    over-permissive expansion accepting what real AWS denies -- into a code mismatch that reads
    like a naming difference.
    """
    r = _probe(awslambda, function_name, op, **args)
    if r.get("ok") is not False:
        raise AssertionError(
            f"{op} SUCCEEDED under the synthesized role; the expanded policy is "
            f"over-permissive. Probe returned {r!r}"
        )
    return r.get("code")


def _error_code(fn) -> str:
    """The AWS error code a call raised. Raises when the call unexpectedly succeeded."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    raise AssertionError("the call succeeded; no error code to assert")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _delete_table_if_present(ddb, table_name: str) -> None:
    """Best-effort table teardown; a table the stack already removed is not an error."""
    try:
        ddb.delete_table(TableName=table_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _delete_log_group_if_present(ctx, log_group: str) -> None:
    """Best-effort log-group teardown; a group Lambda never created is not an error."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=log_group)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _empty_bucket_if_present(s3, bucket: str) -> None:
    """Drain the bucket so the stack delete can remove it (CFN refuses a non-empty bucket)."""
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            objs = [{"Key": o["Key"], "VersionId": o["VersionId"]}
                    for o in page.get("Versions", []) + page.get("DeleteMarkers", [])]
            if objs:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in ("NoSuchBucket", "404"):
            raise


def _delete_stack_and_wait(ctx, stack_name: str, *, timeout_s=900.0) -> None:
    """Delete a CFN stack and wait for DELETE_COMPLETE (teardown; errors swallowed by on_cleanup)."""
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("StackNotFoundException", "ValidationError") or (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" not in exc.response["Error"]["Message"]
            ):
                raise
            return 'GONE'

    _poll_until(_status, lambda s: s in {"DELETE_COMPLETE", "GONE"}, timeout_s=timeout_s,
                interval_s=5.0, description=f"delete stack {stack_name}")


def _create_change_set(ctx, template_body: str, *, timeout_s=300.0) -> dict:
    """Create a CREATE change set with the SAM capabilities and poll it to a terminal status.

    The change set is the projection that shows the transform's output BEFORE anything is
    created, which is the only way to assert synthesis happened at transform time. The stack
    teardown is registered here, before the change set exists, so a REVIEW_IN_PROGRESS shell
    stack is never left behind either.
    """
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    stack_name = _xname(ctx, "stk")
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, stack_name))
    cfn.create_change_set(
        StackName=stack_name,
        ChangeSetName="sim2real-cs1",
        ChangeSetType="CREATE",
        TemplateBody=template_body,
        Tags=_xsvc_tags_kv(),
        Capabilities=["CAPABILITY_AUTO_EXPAND", "CAPABILITY_IAM"],
    )
    described = _poll_until(
        lambda: cfn.describe_change_set(StackName=stack_name, ChangeSetName="sim2real-cs1"),
        lambda d: d["Status"] in {"CREATE_COMPLETE", "FAILED"},
        timeout_s=timeout_s,
        interval_s=3.0,
        description=f"change set for {stack_name}",
    )
    described["stack_name"] = stack_name
    described["change_set_name"] = "sim2real-cs1"
    return described


def _execute_change_set(ctx, stack_name: str, change_set_name: str, *, timeout_s=900.0) -> None:
    """Execute a change set and wait for CREATE_COMPLETE."""
    cfn = ctx.client("cloudformation")
    cfn.execute_change_set(StackName=stack_name, ChangeSetName=change_set_name)
    status = _poll_until(
        lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"],
        lambda s: s.endswith(("_COMPLETE", "_FAILED")),
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {stack_name}",
    )
    assert status == "CREATE_COMPLETE", f"stack {stack_name} ended in {status!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
