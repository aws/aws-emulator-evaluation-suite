"""lf-table-select-grant-readable-through-athena-and-ungranted-table-denied."""
from __future__ import annotations

import json
import re
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lf-table-select-grant-readable-through-athena-and-ungranted-table-denied"
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
    """A Lake Formation SELECT grant makes a registered table readable through Athena with its exact
    rows, while an ungranted sibling is invisible: TABLE_NOT_FOUND in Athena, AccessDeniedException
    on the reader's Glue GetTable, and absent from its GetTables listing."""
    data_bucket = _create_bucket(ctx, "data")
    out_bucket = _create_bucket(ctx, "out")
    s3 = ctx.client("s3")

    granted_rows = "1,alpha,west\n2,beta,east\n"
    s3.put_object(Bucket=data_bucket, Key="data/t_granted/p.csv", Body=granted_rows.encode())
    s3.put_object(Bucket=data_bucket, Key="data/t_ungranted/p.csv", Body=b"9,secret,classified\n")

    db = _create_database(ctx)
    cols = [{"Name": "id", "Type": "bigint"}, {"Name": "name", "Type": "string"},
            {"Name": "zone", "Type": "string"}]
    _create_csv_table(ctx, db, "t_granted", f"s3://{data_bucket}/data/t_granted/", cols)
    _create_csv_table(ctx, db, "t_ungranted", f"s3://{data_bucket}/data/t_ungranted/", cols)

    # The table is created BEFORE its location is registered. Creating a table inside an
    # already-registered location needs DATA_LOCATION_ACCESS, which only a data lake
    # administrator holds implicitly -- and DataLakeSettings is account-global, so a check that
    # appointed itself administrator would strip a concurrent sibling of it on teardown. In this
    # order the check needs no administrator at all: CreateDatabase leaves its creator with
    # grantable permissions on everything in the database.
    reg_role_arn = _create_registration_role(ctx, data_bucket)
    location_arn = f"arn:aws:s3:::{data_bucket}/data/"
    _register_location(ctx, location_arn, reg_role_arn)

    # The precondition that makes enforcement observable at all: the database was created with
    # CreateTableDefaultPermissions=[], so neither table carries the backwards-compatible
    # IAM_ALLOWED_PRINCIPALS grant that would let IAM alone decide access.
    for table in ("t_granted", "t_ungranted"):
        principals = _table_principals(ctx, db, table)
        assert "IAM_ALLOWED_PRINCIPALS" not in principals, (
            f"{table!r} carries IAM_ALLOWED_PRINCIPALS, so Lake Formation is not the "
            f"authority on it and this check would prove nothing; principals were {principals!r}"
        )

    reader_arn = _create_reader_role(ctx, out_bucket)
    _grant(ctx, reader_arn, {"Database": {"Name": db}}, ["DESCRIBE"])
    _grant(ctx, reader_arn, {"Table": {"DatabaseName": db, "Name": "t_granted"}}, ["SELECT"])

    reader = _assume_session(ctx, reader_arn)
    r_athena, r_glue = ctx.client("athena", creds=reader), ctx.client("glue", creds=reader)
    output = f"s3://{out_bucket}/results/"

    # Positive: the granted table reads back exactly the bytes the check wrote. Retried while
    # the grant propagates, so the negative below can be a single decisive attempt.
    qid, state, reason, rows = _read_until_granted(
        r_athena, f'SELECT id, name, zone FROM "{db}"."t_granted" ORDER BY id', db, output)
    assert state == "SUCCEEDED", f"granted table never became readable: {state} / {reason!r}"
    assert rows == [["1", "alpha", "west"], ["2", "beta", "east"]], (
        f"granted table returned {rows!r}, not the two rows the check wrote")

    # Negative: one thing differs -- no SELECT grant. Lake Formation hides the table.
    _, state_no, reason_no = _run_query(
        r_athena, f'SELECT id, name, zone FROM "{db}"."t_ungranted"', db, output)
    assert state_no == "FAILED", (
        f"ungranted table must not be readable, but the query reached {state_no!r}")
    assert reason_no is not None, "a FAILED Athena query must carry a StateChangeReason"
    code_no = _athena_error_code(reason_no)
    assert code_no == "TABLE_NOT_FOUND", (
        f"an ungranted Lake Formation table is invisible, not refused: expected Athena code "
        f"TABLE_NOT_FOUND, got {code_no!r} from reason {reason_no!r}")
    # Column 28 is where the table reference starts in the fixed SQL text above.
    assert reason_no == (f"TABLE_NOT_FOUND: line 1:28: Table "
                         f"'awsdatacatalog.{db}.t_ungranted' does not exist"), (
        f"the failure must name the table it hid, got {reason_no!r}")

    # The reader's own catalog listing comes first, and does double duty: it shows the ungranted
    # table subtracted from the catalog, and it proves the reader's Glue permissions are already
    # effective -- so the refusal asserted next can only be a Lake Formation decision and not the
    # reader's freshly created IAM policy still propagating.
    visible = _tables_until(r_glue, db, ["t_granted"])
    assert visible == ["t_granted"], (
        f"the reader must see only the table it was granted, saw {visible!r}")

    # The effect is absent on a direct read too, not only in the listing and the query engine.
    code, message = _error_code(lambda: r_glue.get_table(DatabaseName=db, Name="t_ungranted"))
    assert code == "AccessDeniedException", (
        f"reader's catalog read of the ungranted table returned {code!r}")
    assert message == ("Insufficient Lake Formation permission(s): "
                       "Required Describe on t_ungranted"), (
        f"reader's catalog read of the ungranted table refused with {message!r}")

    # Positive control on the same call the negative used: the admin still sees both tables,
    # so the omission above is Lake Formation filtering and not a broken catalog.
    admin_visible = _list_table_names(ctx.client("glue"), db)
    assert admin_visible == ["t_granted", "t_ungranted"], (
        f"admin must still see both tables, saw {admin_visible!r}")




def _sql_name(ctx: Any, prefix: str) -> str:
    return ctx.unique_name(prefix).replace("-", "_").lower()


def _create_bucket(ctx: Any, kind: str) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name(f"sim2real-lf-{kind}-").replace("_", "-").lower()
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
    """The role Lake Formation itself assumes to read the registered location."""
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


def _table_principals(ctx: Any, db: str, table: str) -> list:
    lf = ctx.client("lakeformation")
    seen, token = set(), None
    while True:
        kwargs: dict[str, Any] = {
            "Resource": {"Table": {"DatabaseName": db, "Name": table}}}
        if token:
            kwargs["NextToken"] = token
        resp = lf.list_permissions(**kwargs)
        for p in resp.get("PrincipalResourcePermissions", []):
            seen.add(p["Principal"]["DataLakePrincipalIdentifier"])
        token = resp.get("NextToken")
        if not token:
            return sorted(seen)


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
            ctx.on_cleanup(lambda: lf.revoke_permissions(
                Principal={"DataLakePrincipalIdentifier": principal},
                Resource=resource, Permissions=permissions))
            return
        except ClientError as e:
            err = e.response["Error"]
            if not (err["Code"] == "InvalidInputException"
                    and "Invalid principal" in err["Message"]):
                raise
            last = err
            time.sleep(4)
    raise AssertionError(f"Lake Formation never accepted principal {principal}: {last}")


def _assume_session(ctx: Any, role_arn: str, timeout_s: float = 90.0) -> dict:
    """The role's temporary credentials, for ``ctx.client(..., creds=...)``."""
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


def _rows(athena, qid: str) -> list:
    out = []
    for page in athena.get_paginator("get_query_results").paginate(QueryExecutionId=qid):
        for row in page["ResultSet"]["Rows"]:
            out.append([d.get("VarCharValue") for d in row["Data"]])
    return out[1:]  # the first row of a SELECT result set is the column header


def _list_table_names(glue, db: str) -> list:
    names = []
    for page in glue.get_paginator("get_tables").paginate(DatabaseName=db):
        names.extend(t["Name"] for t in page["TableList"])
    return sorted(names)


def _error_code(fn) -> tuple[str, str]:
    """Return fn()'s botocore error code and message. An unexpected SUCCESS raises, so serving data
    real AWS withholds is never reported as a mere code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED: {result!r}")



def _tables_until(glue_client, db: str, expected: list, timeout_s: float = 45.0) -> list:
    """Poll the reader's catalog listing until it settles on `expected`. Safe in the only
    direction that matters: a listing showing MORE tables than expected never matches, so this
    absorbs a grant still propagating without ever excusing an over-permissive answer."""
    deadline = time.monotonic() + timeout_s
    seen: list = []
    while time.monotonic() < deadline:
        try:
            seen = _list_table_names(glue_client, db)
            if seen == expected:
                return seen
        except ClientError as e:
            if e.response["Error"]["Code"] not in _SESSION_NOT_READY:
                raise
        time.sleep(3)
    return seen

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
