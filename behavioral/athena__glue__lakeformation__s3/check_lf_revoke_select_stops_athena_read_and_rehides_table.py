"""lf-revoke-select-stops-athena-read-and-rehides-table."""
from __future__ import annotations

import json
import re
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lf-revoke-select-stops-athena-read-and-rehides-table"
GROUP = "permission-enforcement"
SERVICES = ["athena", "glue", "lakeformation", "s3"]

# A session just minted by AssumeRole is not usable everywhere the instant it is returned: the
# temporary credentials themselves can be rejected (UnrecognizedClientException /
# InvalidClientTokenId) and the role's freshly created inline policy can still be propagating
# (AccessDenied on the IAM ACTION). Neither is a Lake Formation decision -- Lake Formation
# refuses a query by FAILING it with a TABLE_NOT_FOUND / COLUMN_NOT_FOUND reason, and refuses a
# catalog read with AccessDeniedException whose message names a missing Lake Formation
# permission -- so waiting these out at first use weakens no assertion in this check.
_SESSION_NOT_READY = ("AccessDenied", "AccessDeniedException", "UnrecognizedClientException",
                      "InvalidClientTokenId")

# Athena's own engine faults: never a Lake Formation verdict, so _run_query retries them.
_ATHENA_TRANSIENT = ("INTERNAL_ERROR_QUERY_ENGINE", "INTERNAL_ERROR_FRONTEND")


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e",
      "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Revoking a Lake Formation SELECT grant withdraws working access: the Athena query that
    returned the table's rows stops resolving it, the reader's Glue describe reverts to
    AccessDeniedException, and the grant disappears from ListPermissions."""
    data_bucket = _create_bucket(ctx, "data")
    out_bucket = _create_bucket(ctx, "out")
    ctx.client("s3").put_object(Bucket=data_bucket, Key="data/t_rev/p.csv",
                               Body=b"1,alpha,west\n2,beta,east\n")

    db = _create_database(ctx)
    _create_csv_table(ctx, db, "t_rev", f"s3://{data_bucket}/data/t_rev/",
                      [{"Name": "id", "Type": "bigint"}, {"Name": "name", "Type": "string"},
                       {"Name": "zone", "Type": "string"}])

    # The table is created BEFORE its location is registered. Creating a table inside an
    # already-registered location needs DATA_LOCATION_ACCESS, which only a data lake
    # administrator holds implicitly -- and DataLakeSettings is account-global, so a check that
    # appointed itself administrator would strip a concurrent sibling of it on teardown. In this
    # order the check needs no administrator at all: CreateDatabase leaves its creator with
    # grantable permissions on everything in the database.
    reg_role_arn = _create_registration_role(ctx, data_bucket)
    location_arn = f"arn:aws:s3:::{data_bucket}/data/"
    _register_location(ctx, location_arn, reg_role_arn)

    reader_arn = _create_reader_role(ctx, out_bucket)
    _grant(ctx, reader_arn, {"Database": {"Name": db}}, ["DESCRIBE"])
    table_resource = {"Table": {"DatabaseName": db, "Name": "t_rev"}}
    _grant(ctx, reader_arn, table_resource, ["SELECT"])

    reader = _assume_creds(ctx, reader_arn)
    r_athena, r_glue = ctx.client("athena", creds=reader), ctx.client("glue", creds=reader)
    output = f"s3://{out_bucket}/results/"
    sql = f'SELECT id, name, zone FROM "{db}"."t_rev" ORDER BY id'

    # State 1 -- the grant is in force. This is the positive control for the whole check: the
    # denial asserted later means nothing unless this read demonstrably worked first.
    _, state, reason, rows = _read_until_granted(r_athena, sql, db, output)
    assert state == "SUCCEEDED", f"granted table never became readable: {state} / {reason!r}"
    assert rows == [["1", "alpha", "west"], ["2", "beta", "east"]], (
        f"before the revoke the table returned {rows!r}, not the two rows the check wrote")
    described = _columns_until(r_glue, db, "t_rev", ["id", "name", "zone"])
    assert described == ["id", "name", "zone"], (
        f"before the revoke the reader must be able to describe the table, saw {described!r}")

    # Break exactly one thing: withdraw the SELECT grant. Nothing else changes.
    _revoke(ctx, reader_arn, table_resource, ["SELECT"])

    # State 2 -- the same query, the same credentials, the same table. Polled because
    # revocation propagates; the assertion is that it converges on refusal.
    state_after, reason_after = _read_until_revoked(r_athena, sql, db, output)
    assert state_after == "FAILED", (
        f"after revoking SELECT the read must stop working, but it reached {state_after!r}")
    assert reason_after is not None, "a FAILED Athena query must carry a StateChangeReason"
    code_after = _athena_error_code(reason_after)
    assert code_after == "TABLE_NOT_FOUND", (
        f"a revoked table is re-hidden rather than refused: expected TABLE_NOT_FOUND, got "
        f"{code_after!r} from reason {reason_after!r}")
    expected_reason = (
        f"TABLE_NOT_FOUND: line 1:28: Table 'awsdatacatalog.{db}.t_rev' does not exist")
    assert reason_after == expected_reason, (
        f"the revoked read failed with reason {reason_after!r}, expected {expected_reason!r}")

    # The effect is absent in the catalog too: the describe that succeeded above now fails.
    code, message = _denied_until(lambda: r_glue.get_table(DatabaseName=db, Name="t_rev"),
                                  "AccessDeniedException")
    assert code == "AccessDeniedException", (
        f"after the revoke the reader's catalog read returned {code!r}")
    expected_message = "Insufficient Lake Formation permission(s): Required Describe on t_rev"
    assert message == expected_message, (
        f"the reader's refused catalog read said {message!r}, expected {expected_message!r}")

    # And the grant is gone from Lake Formation's own record of it, not merely ineffective.
    remaining = _principal_table_permissions(ctx, reader_arn, db, "t_rev")
    assert remaining == [], (
        f"revoked SELECT still recorded for the reader on t_rev: {remaining!r}")

    # Restore: re-grant SELECT. The identical query, broken above by that one revoke, must
    # resolve the table and read its rows again -- pinning the refusal to the grant rather than
    # to some other change this check made.
    _grant(ctx, reader_arn, table_resource, ["SELECT"])
    _, restored_state, restored_reason, restored_rows = _read_until_granted(
        r_athena, sql, db, output)
    assert restored_state == "SUCCEEDED", (
        f"after restoring SELECT the read must work again, but reached {restored_state!r} / "
        f"{restored_reason!r}")
    assert restored_rows == [["1", "alpha", "west"], ["2", "beta", "east"]], (
        f"after restoring SELECT the table returned {restored_rows!r}, not the original two "
        f"rows")




def _sql_name(ctx: Any, prefix: str) -> str:
    return ctx.unique_name(prefix).replace("-", "_").lower()


def _create_bucket(ctx: Any, kind: str) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name(f"sim2real-lf-{kind}-").replace("_", "-").lower()
    # us-east-1 is S3's legacy sentinel region: CreateBucketConfiguration is rejected there and
    # required everywhere else.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket,
                         CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(Bucket=bucket,
                          Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return bucket


def _empty_and_delete_bucket(ctx: Any, bucket: str) -> None:
    s3 = ctx.client("s3")
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        objs = page.get("Contents", [])
        if objs:
            s3.delete_objects(Bucket=bucket,
                              Delete={"Objects": [{"Key": o["Key"]} for o in objs]})
    s3.delete_bucket(Bucket=bucket)


def _create_registration_role(ctx: Any, data_bucket: str) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-lf-reg-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "lakeformation.amazonaws.com"},
        "Action": "sts:AssumeRole"}]}
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                          Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(RoleName=name, PolicyName="lf-data-location",
                        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
                            {"Effect": "Allow",
                             "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
                             "Resource": f"arn:aws:s3:::{data_bucket}/*"},
                            {"Effect": "Allow",
                             "Action": ["s3:ListBucket", "s3:GetBucketLocation"],
                             "Resource": f"arn:aws:s3:::{data_bucket}"}]}))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name,
                                                  PolicyName="lf-data-location"))
    return arn


def _register_location(ctx: Any, location_arn: str, role_arn: str,
                       timeout_s: float = 120.0) -> None:
    """RegisterResource validates that Lake Formation can assume the role, which lags role
    creation. No API reports IAM propagation, so the call is retried until a deadline."""
    lf = ctx.client("lakeformation")
    left = ctx.time_left()
    deadline = time.monotonic() + (timeout_s if left is None else min(timeout_s, left))
    last: dict | None = None
    while time.monotonic() < deadline:
        try:
            lf.register_resource(ResourceArn=location_arn, RoleArn=role_arn,
                                 UseServiceLinkedRole=False)
            ctx.on_cleanup(lambda: lf.deregister_resource(ResourceArn=location_arn))
            info = lf.describe_resource(ResourceArn=location_arn)["ResourceInfo"]
            assert info["RoleArn"] == role_arn, (
                f"registered location reports role {info['RoleArn']!r}, not {role_arn!r}")
            return
        except ClientError as e:
            err = e.response["Error"]
            if err["Code"] not in ("InvalidInputException", "AccessDeniedException"):
                raise
            last = err
            time.sleep(2)
    raise AssertionError(f"could not register {location_arn} within {timeout_s}s: {last}")


def _create_database(ctx: Any) -> str:
    """CreateTableDefaultPermissions=[] suppresses the backwards-compatible
    IAM_ALLOWED_PRINCIPALS grant for tables created in this database, per database, without
    mutating the account-global CreateTableDefaultPermissions default."""
    glue = ctx.client("glue")
    name = _sql_name(ctx, "sim2real_lf_db_")
    glue.create_database(DatabaseInput={"Name": name, "CreateTableDefaultPermissions": []})
    ctx.on_cleanup(lambda: glue.delete_database(Name=name))
    return name


def _create_csv_table(ctx: Any, db: str, table: str, location: str, columns: list) -> str:
    glue = ctx.client("glue")
    glue.create_table(DatabaseName=db, TableInput={
        "Name": table, "TableType": "EXTERNAL_TABLE", "Parameters": {"EXTERNAL": "TRUE"},
        "StorageDescriptor": {
            "Columns": columns, "Location": location,
            "InputFormat": "org.apache.hadoop.mapred.TextInputFormat",
            "OutputFormat": "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
            "SerdeInfo": {"SerializationLibrary":
                          "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe",
                          "Parameters": {"field.delim": ","}}}})
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=db, Name=table))
    return table


def _create_reader_role(ctx: Any, out_bucket: str) -> str:
    """A reader with Athena, Glue metadata and lakeformation:GetDataAccess, and S3 rights ONLY
    on the results bucket: every byte of table data it can see must come through Lake
    Formation's vended credentials, never its own IAM policy."""
    iam, sts = ctx.client("iam"), ctx.client("sts")
    account = sts.get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-lf-rdr-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
        "Action": "sts:AssumeRole"}]}
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                          Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(RoleName=name, PolicyName="lf-reader",
                        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
                            {"Effect": "Allow",
                             "Action": ["athena:StartQueryExecution", "athena:GetQueryExecution",
                                        "athena:GetQueryResults", "athena:GetWorkGroup",
                                        "athena:StopQueryExecution"], "Resource": "*"},
                            {"Effect": "Allow",
                             "Action": ["glue:GetDatabase", "glue:GetDatabases", "glue:GetTable",
                                        "glue:GetTables", "glue:GetPartition",
                                        "glue:GetPartitions"], "Resource": "*"},
                            {"Effect": "Allow", "Action": ["lakeformation:GetDataAccess"],
                             "Resource": "*"},
                            {"Effect": "Allow",
                             "Action": ["s3:GetObject", "s3:PutObject",
                                        "s3:AbortMultipartUpload"],
                             "Resource": f"arn:aws:s3:::{out_bucket}/*"},
                            {"Effect": "Allow",
                             "Action": ["s3:ListBucket", "s3:GetBucketLocation"],
                             "Resource": f"arn:aws:s3:::{out_bucket}"}]}))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="lf-reader"))
    return arn


def _grant(ctx: Any, principal: str, resource: dict, permissions: list,
           timeout_s: float = 120.0) -> None:
    """Lake Formation resolves the principal against IAM, which lags role creation with
    InvalidInputException 'Invalid principal'. Bounded retry at first use of the permission."""
    lf = ctx.client("lakeformation")
    deadline = time.monotonic() + timeout_s
    last: dict | None = None
    while time.monotonic() < deadline:
        try:
            lf.grant_permissions(Principal={"DataLakePrincipalIdentifier": principal},
                                 Resource=resource, Permissions=permissions)
            ctx.on_cleanup(lambda: _revoke_if_held(lf, principal, resource, permissions))
            return
        except ClientError as e:
            err = e.response["Error"]
            if not (err["Code"] == "InvalidInputException"
                    and "Invalid principal" in err["Message"]):
                raise
            last = err
            time.sleep(4)
    raise AssertionError(f"Lake Formation never accepted principal {principal}: {last}")


def _revoke_if_held(lf, principal: str, resource: dict, permissions: list) -> None:
    """Teardown revoke; a grant the check itself already revoked is not a leak."""
    try:
        lf.revoke_permissions(Principal={"DataLakePrincipalIdentifier": principal},
                              Resource=resource, Permissions=permissions)
    except ClientError as e:
        if not (e.response["Error"]["Code"] == "InvalidInputException"
                and e.response["Error"]["Message"].startswith("No permissions revoked")):
            raise


def _revoke(ctx: Any, principal: str, resource: dict, permissions: list) -> None:
    ctx.client("lakeformation").revoke_permissions(
        Principal={"DataLakePrincipalIdentifier": principal},
        Resource=resource, Permissions=permissions)


def _principal_table_permissions(ctx: Any, principal: str, db: str, table: str) -> list:
    """Every permission Lake Formation still records for this principal on this table."""
    lf = ctx.client("lakeformation")
    found, token = [], None
    while True:
        kwargs: dict[str, Any] = {
            "Principal": {"DataLakePrincipalIdentifier": principal},
            "Resource": {"Table": {"DatabaseName": db, "Name": table}}}
        if token:
            kwargs["NextToken"] = token
        resp = lf.list_permissions(**kwargs)
        for p in resp.get("PrincipalResourcePermissions", []):
            if p["Principal"]["DataLakePrincipalIdentifier"] == principal:
                found.extend(p.get("Permissions", []))
        token = resp.get("NextToken")
        if not token:
            return sorted(set(found))


def _assume_creds(ctx: Any, role_arn: str, timeout_s: float = 90.0) -> dict:
    sts = ctx.client("sts")
    deadline = time.monotonic() + timeout_s
    last: Exception | None = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(RoleArn=role_arn,
                                    RoleSessionName=ctx.unique_name("s-")[:60])["Credentials"]
            return {"aws_access_key_id": creds["AccessKeyId"],
                    "aws_secret_access_key": creds["SecretAccessKey"],
                    "aws_session_token": creds["SessionToken"]}
        except ClientError as e:
            if e.response["Error"]["Code"] != "AccessDenied":
                raise
            last = e
            time.sleep(3)
    raise AssertionError(f"could not assume {role_arn} within {timeout_s}s: {last}")


def _start_query(athena, sql: str, database: str, output: str,
                 timeout_s: float = 120.0) -> str:
    """Wait for the reader's session to become usable at its first use, per _SESSION_NOT_READY."""
    deadline = time.monotonic() + timeout_s
    last: dict | None = None
    while time.monotonic() < deadline:
        try:
            return athena.start_query_execution(
                QueryString=sql, QueryExecutionContext={"Database": database},
                ResultConfiguration={"OutputLocation": output})["QueryExecutionId"]
        except ClientError as e:
            err = e.response["Error"]
            code, message = err["Code"], err.get("Message", "")
            # Athena verifies the results location with the CALLER's credentials, so the reader's
            # own S3 grant on its results bucket still propagating surfaces here as
            # InvalidRequestException "Unable to verify/create output bucket" rather than as an
            # access denial. Matched on the message so a genuinely malformed request still fails.
            retryable = code in _SESSION_NOT_READY or (
                code == "InvalidRequestException" and "output bucket" in message)
            if not retryable:
                raise
            last = err
            time.sleep(3)
    raise AssertionError(
        f"the reader's session never became usable within {timeout_s}s: {last}")


def _athena_error_code(reason: str | None) -> str:
    """Athena reports a failed query's code in two shapes: "CODE: message" when the query could
    not be resolved (TABLE_NOT_FOUND, COLUMN_NOT_FOUND -- how Lake Formation enforcement
    surfaces), and "[ErrorCode: CODE] message" for an engine fault. Splitting on the colon alone
    reads the second shape as "[ErrorCode"."""
    if not reason:
        return ""
    m = re.match(r"\s*\[ErrorCode:\s*([A-Z_]+)\]", reason)
    return m.group(1) if m else reason.split(":", 1)[0].strip()


def _run_query(athena, sql: str, database: str, output: str, timeout_s: float = 120.0,
               attempts: int = 4):
    """Run one query to a terminal state, retrying an Athena engine fault (_ATHENA_TRANSIENT).
    Every other outcome is returned as-is, so a Lake Formation refusal is never retried away."""
    qid = state = reason = None
    for attempt in range(attempts):
        qid = _start_query(athena, sql, database, output)
        deadline = time.monotonic() + timeout_s
        state = None
        while time.monotonic() < deadline:
            status = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]
            state = status["State"]
            if state in ("SUCCEEDED", "FAILED", "CANCELLED"):
                reason = status.get("StateChangeReason")
                break
            time.sleep(1.5)
        else:
            raise AssertionError(f"query {qid} did not finish within {timeout_s}s "
                                 f"(last {state!r})")
        if state == "FAILED" and _athena_error_code(reason) in _ATHENA_TRANSIENT \
                and attempt + 1 < attempts:
            time.sleep(4)
            continue
        return qid, state, reason
    return qid, state, reason


def _read_until_granted(athena, sql: str, database: str, output: str,
                        timeout_s: float = 90.0):
    """Poll the observable condition that a fresh grant has taken effect: the table becomes
    resolvable. Until then Lake Formation hides it, so TABLE_NOT_FOUND is the retryable state."""
    deadline = time.monotonic() + timeout_s
    qid = state = reason = None
    while time.monotonic() < deadline:
        qid, state, reason = _run_query(athena, sql, database, output)
        if state == "SUCCEEDED":
            return qid, state, reason, _rows(athena, qid)
        # TABLE_NOT_FOUND is the grant not having landed yet, and an Athena engine fault is a
        # fault in the engine -- both deserve another attempt inside the deadline. Any other
        # failure is a real verdict, returned for the caller to assert on.
        if state == "FAILED" and reason and _athena_error_code(reason) not in \
                ("TABLE_NOT_FOUND",) + _ATHENA_TRANSIENT:
            return qid, state, reason, []
        time.sleep(4)
    return qid, state, reason, []


def _read_until_revoked(athena, sql: str, database: str, output: str,
                        timeout_s: float = 90.0):
    """The mirror of _read_until_granted: poll until the revoke has taken effect and the read
    stops succeeding. Converging on a failure is the observable condition here."""
    deadline = time.monotonic() + timeout_s
    state = reason = None
    while time.monotonic() < deadline:
        _, state, reason = _run_query(athena, sql, database, output)
        # Converge specifically on Lake Formation re-hiding the table, not merely on the query
        # ceasing to succeed: an engine fault that outlasted _run_query's retries would
        # otherwise be read as the revoke having taken effect, passing for the wrong reason.
        if state == "FAILED" and _athena_error_code(reason) == "TABLE_NOT_FOUND":
            return state, reason
        time.sleep(4)
    return state, reason


def _rows(athena, qid: str) -> list:
    out = []
    for page in athena.get_paginator("get_query_results").paginate(QueryExecutionId=qid):
        for row in page["ResultSet"]["Rows"]:
            out.append([d.get("VarCharValue") for d in row["Data"]])
    return out[1:]  # the first row of a SELECT result set is the column header



def _columns_until(glue_client, db: str, table: str, expected: list,
                   timeout_s: float = 45.0) -> list | str:
    """Poll the reader's catalog view until it settles on `expected`: a grant reaches Athena before
    Glue GetTable. A schema with MORE columns never matches, so over-permission still fails."""
    deadline = time.monotonic() + timeout_s
    seen: list | str | None = None
    while time.monotonic() < deadline:
        try:
            seen = [c["Name"] for c in glue_client.get_table(
                DatabaseName=db, Name=table)["Table"]["StorageDescriptor"]["Columns"]]
            if seen == expected:
                return seen
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code not in _SESSION_NOT_READY + ("EntityNotFoundException",):
                raise
            seen = code
        time.sleep(3)
    return seen if seen is not None else []


def _denied_until(fn, code: str, timeout_s: float = 45.0) -> tuple[str, str]:
    """Poll until fn() is refused with `code`; returns the last ``(code, message)``. This absorbs
    revocation propagation only: a call that keeps SUCCEEDING never satisfies it."""
    deadline = time.monotonic() + timeout_s
    last = ("SUCCEEDED", "")
    while time.monotonic() < deadline:
        try:
            fn()
        except ClientError as e:
            last = (e.response["Error"]["Code"], e.response["Error"].get("Message", ""))
            if last[0] == code:
                return last
        time.sleep(3)
    return last

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
