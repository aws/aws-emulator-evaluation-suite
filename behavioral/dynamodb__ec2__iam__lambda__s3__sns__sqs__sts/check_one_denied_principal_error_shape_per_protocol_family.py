"""one-denied-principal-error-shape-per-protocol-family."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "one-denied-principal-error-shape-per-protocol-family"
GROUP = "protocol-family-error-shapes"
SERVICES = ["dynamodb", "ec2", "iam", "lambda", "s3", "sns", "sqs", "sts"]


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _assume_until_consistent(sts_admin, role_arn, timeout_s=90):
    """AssumeRole, retrying AccessDenied until a fresh role's trust policy propagates (bounded).

    No API reports trust-policy propagation as complete, so the retry is the propagation wait.
    """
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            return sts_admin.assume_role(RoleArn=role_arn, RoleSessionName="probe")["Credentials"]
        except ClientError as exc:
            last = exc.response.get("Error", {}).get("Code")
            time.sleep(3)
    raise AssertionError(f"role never became assumable within {timeout_s}s; last error {last!r}")


def _denied_call(ctx, service, creds, call):
    """Run ``call`` against ``service`` as the denied principal; raises if it succeeds.

    Returns (error_code, http_status, content_type, body, headers, message).
    """
    client = ctx.client(service, creds=creds)
    captured = {}

    def before_parse(**kwargs):
        rd = kwargs.get("response_dict") or {}
        captured["status"] = rd.get("status_code")
        captured["headers"] = dict(rd.get("headers") or {})
        captured["body"] = (rd.get("body") or b"")[:2000].decode("utf-8", "replace")

    client.meta.events.register("before-parse.*.*", before_parse)
    try:
        call(client)
    except ClientError as exc:
        return (
            exc.response.get("Error", {}).get("Code"),
            exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode"),
            captured.get("headers", {}).get("Content-Type"),
            captured.get("body", ""),
            captured.get("headers", {}),
            exc.response.get("Error", {}).get("Message"),
        )
    raise AssertionError(
        f"{service} call unexpectedly SUCCEEDED for a principal with zero attached permissions"
    )


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """One permissionless role session is denied once per wire-protocol family, each in its own shape.

    DynamoDB answers 400 and SQS 403 on the same JSON protocol, SQS adds x-amzn-query-error, and
    IAM, SNS and STS share one XML envelope with differing codes; asserted side by side.
    """
    iam = ctx.client("iam")
    sts_admin = ctx.client("sts")

    role_name = ctx.unique_name("sim2real-xsvc-denied-")
    # The account root, not the calling identity, is the trusted principal.
    trust_policy = (
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
        f'"Principal":{{"AWS":"arn:aws:iam::{ctx.account}:root"}},"Action":"sts:AssumeRole"}}]}}'
    )
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=trust_policy
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    # No policy of any kind is ever attached -- the "break exactly one thing" here is the
    # permanent absence of a permission, not a transient misconfiguration.
    attached = iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]
    inline = iam.list_role_policies(RoleName=role_name)["PolicyNames"]
    assert attached == [], f"expected a bare role, found attached policies {attached!r}"
    assert inline == [], f"expected a bare role, found inline policies {inline!r}"

    creds_raw = _assume_until_consistent(sts_admin, role_arn, timeout_s=_budget_s(ctx, 90.0))
    denied_creds = {
        "aws_access_key_id": creds_raw["AccessKeyId"],
        "aws_secret_access_key": creds_raw["SecretAccessKey"],
        "aws_session_token": creds_raw["SessionToken"],
    }

    # Positive control: GetCallerIdentity needs no identity-based permission at all. If this
    # failed, every denial below would be a broken-credential artifact, not a policy decision.
    control = ctx.client("sts", creds=denied_creds).get_caller_identity()
    expected_control_arn = f"arn:aws:sts::{ctx.account}:assumed-role/{role_name}/probe"
    assert control["Arn"] == expected_control_arn, (
        f"control GetCallerIdentity returned {control['Arn']!r}, expected "
        f"{expected_control_arn!r}"
    )
    acct, region = ctx.account, ctx.region

    def denial(action: str, resource: str | None) -> str:
        """The implicit-deny message every family carries, built from the denied session."""
        on = f" on resource: {resource}" if resource is not None else ""
        return (f"User: {expected_control_arn} is not authorized to perform: {action}{on} "
                f"because no identity-based policy allows the {action} action")

    # --- awsJson1_0: DynamoDB ---
    code, status, ctype, body, headers, message = _denied_call(
        ctx, "dynamodb", denied_creds, lambda c: c.list_tables(Limit=1)
    )
    assert code == "AccessDeniedException", f"dynamodb ListTables denial code was {code!r}"
    want = denial("dynamodb:ListTables", f"arn:aws:dynamodb:{region}:{acct}:table/*")
    assert message == want, f"dynamodb denial message was {message!r}, expected {want!r}"
    assert status == 400, f"dynamodb ListTables denial HTTP status was {status!r}, expected 400"
    assert ctype == "application/x-amz-json-1.0", f"dynamodb Content-Type was {ctype!r}"
    assert '"__type"' in body, f"dynamodb awsJson1_0 body carries no __type field: {body!r}"
    assert "x-amzn-query-error" not in headers, (
        "dynamodb is plain awsJson1_0 and must not carry the awsQueryCompatible shim header"
    )

    # --- awsJson1_0 + awsQueryCompatible: SQS ---
    code, status, ctype, body, headers, message = _denied_call(
        ctx, "sqs", denied_creds, lambda c: c.list_queues()
    )
    assert code == "AccessDenied", (
        f"sqs ListQueues denial code was {code!r}, expected the SHORT query-style code "
        "('AccessDenied', not 'AccessDeniedException') that the awsQueryCompatible shim remaps "
        "the raw __type into"
    )
    # SQS names its action lower-case and its resource with an empty queue segment.
    want = denial("sqs:listqueues", f"arn:aws:sqs:{region}:{acct}:")
    assert message == want, f"sqs denial message was {message!r}, expected {want!r}"
    assert status == 403, (
        f"sqs ListQueues denial HTTP status was {status!r}, expected 403 -- the same "
        "AccessDenied-class decision that DynamoDB (same base JSON protocol) answers with 400"
    )
    assert ctype == "application/x-amz-json-1.0", f"sqs Content-Type was {ctype!r}"
    assert '"__type"' in body, f"sqs body still carries the raw JSON __type field: {body!r}"
    query_error = headers.get("x-amzn-query-error", "")
    assert query_error.startswith("AccessDenied;"), (
        f"sqs x-amzn-query-error was {query_error!r}; this header is the mechanism that lets "
        "botocore report the short code instead of the body's own __type"
    )

    # --- ec2Query: EC2 ---
    code, status, ctype, body, _headers, message = _denied_call(
        ctx, "ec2", denied_creds, lambda c: c.describe_instances(MaxResults=5)
    )
    assert code == "UnauthorizedOperation", f"ec2 DescribeInstances denial code was {code!r}"
    want = "You are not authorized to perform this operation. " + denial("ec2:DescribeInstances", None)
    assert message == want, f"ec2 denial message was {message!r}, expected {want!r}"
    assert status == 403, f"ec2 DescribeInstances denial HTTP status was {status!r}"
    assert ctype.startswith("text/xml"), f"ec2 Content-Type was {ctype!r}"
    assert body.lstrip().startswith('<?xml'), f"ec2 body did not start as XML: {body[:80]!r}"
    assert "<Response><Errors>" in body, (
        f"ec2's ec2Query envelope is <Response><Errors>..., not the awsQuery <ErrorResponse> "
        f"wrapper; got {body[:200]!r}"
    )
    assert "<ErrorResponse" not in body, "ec2 must not share awsQuery's <ErrorResponse> wrapper"

    # --- awsQuery: IAM, SNS, STS (one XML envelope, three different error-code vocabularies) ---
    query_family = {
        "iam": ("AccessDenied", lambda c: c.list_roles(MaxItems=1),
                denial("iam:ListRoles", f"arn:aws:iam::{acct}:role/")),
        "sns": ("AuthorizationError", lambda c: c.list_topics(),
                denial("SNS:ListTopics", f"arn:aws:sns:{region}:{acct}:*")),
        # STS alone omits the "because ..." clause: a role session assuming a role is judged
        # against the target's trust policy, so no identity-policy reason is given.
        "sts": ("AccessDenied", lambda c: c.assume_role(RoleArn=role_arn, RoleSessionName="x2"),
                f"User: {expected_control_arn} is not authorized to perform: sts:AssumeRole on "
                f"resource: {role_arn}"),
    }
    for service, (expected_code, call, want) in query_family.items():
        code, status, ctype, body, _headers, message = _denied_call(ctx, service, denied_creds, call)
        assert code == expected_code, f"{service} denial code was {code!r}, expected {expected_code!r}"
        assert message == want, f"{service} denial message was {message!r}, expected {want!r}"
        assert status == 403, f"{service} denial HTTP status was {status!r}, expected 403"
        assert ctype.startswith("text/xml"), f"{service} Content-Type was {ctype!r}"
        assert body.lstrip().startswith("<ErrorResponse"), (
            f"{service} is awsQuery and must wrap its error in <ErrorResponse>; got "
            f"{body[:120]!r}"
        )

    # --- restJson1: Lambda ---
    code, status, ctype, body, _headers, message = _denied_call(
        ctx, "lambda", denied_creds, lambda c: c.list_functions(MaxItems=1)
    )
    assert code == "AccessDeniedException", f"lambda ListFunctions denial code was {code!r}"
    want = denial("lambda:ListFunctions", "*")
    assert message == want, f"lambda denial message was {message!r}, expected {want!r}"
    assert status == 403, f"lambda ListFunctions denial HTTP status was {status!r}"
    assert ctype == "application/json", f"lambda Content-Type was {ctype!r}"
    assert '"__type"' not in body, (
        f"lambda is restJson1, which carries its error type in a header, not a body __type "
        f"field like awsJson1_0 does; got body {body[:120]!r}"
    )

    # --- restXml: S3 ---
    code, status, ctype, body, _headers, message = _denied_call(
        ctx, "s3", denied_creds, lambda c: c.list_buckets()
    )
    assert code == "AccessDenied", f"s3 ListBuckets denial code was {code!r}"
    want = denial("s3:ListAllMyBuckets", None)
    assert message == want, f"s3 denial message was {message!r}, expected {want!r}"
    assert status == 403, f"s3 ListBuckets denial HTTP status was {status!r}"
    assert ctype == "application/xml", f"s3 Content-Type was {ctype!r}"
    assert body.lstrip().startswith("<Error>") or body.lstrip().startswith('<?xml'), (
        f"s3 body did not start as a bare restXml <Error>: {body[:80]!r}"
    )
    assert "<ErrorResponse" not in body, (
        f"s3's restXml <Error> must not be wrapped like awsQuery's <ErrorResponse>; got "
        f"{body[:160]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
