"""glue-spark-parquet-partition-layout-and-footer-aggregates-and-a-malformed-row-fails-the-run."""
from __future__ import annotations

import json
import struct
import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = (
    "glue-spark-parquet-partition-layout-and-footer-aggregates-and-a-malformed-row-fails-the-run"
)
GROUP = 'jobs'
SERVICES = ['glue', 's3']

# Two sequential Glue Spark runs share this one hard deadline, so every wait in the check is
# bounded. A Glue 4.0 G.1X x2 run takes about 45-85 s from start to terminal state.
_TOTAL_DEADLINE_S = 1200.0

_ROWS = 5000
# Deliberately 7 characters each, not "NA"/"EMEA": one assertion below is that the partition
# VALUE does not appear anywhere in the part file's bytes, and a two-byte needle would collide
# by chance inside a Snappy-compressed page often enough to make the check flaky.
_REGIONS = ("NORTHAM", "EUROPE1", "ASIAPAC", "LATAMER")


def _build_input() -> tuple[bytes, dict]:
    """The one input CSV, plus the per-region aggregates it implies. Pure arithmetic."""
    lines = []
    agg: dict[str, list] = {r: [0, 0.0] for r in _REGIONS}
    for i in range(1, _ROWS + 1):
        region = _REGIONS[i % 4]
        amount = round((i % 97) + 0.25, 2)
        lines.append(f"{i},{region},{amount}")
        agg[region][0] += 1
        agg[region][1] += amount
    csv = ("order_id,region,amount\n" + "\n".join(lines) + "\n").encode()
    return csv, {r: (n, round(total, 6)) for r, (n, total) in agg.items()}


_CSV, _EXPECTED = _build_input()

# Exactly one cell differs from a well-formed row: `amount` is not a double. Everything else
# about the second run -- job, script, role, worker shape -- is identical to the first.
_BAD_CSV = (b"order_id,region,amount\n1,NORTHAM,1.5\n2,NORTHAM,not-a-number\n"
            b"3,EUROPE1,2.5\n")

# Real PySpark. groupBy/agg is a shuffle; partitionBy("region") is a Hive-style write that
# must place rows under region=<value>/ by VALUE and drop the column from the file itself.
# FAILFAST makes the malformed-row arm a run failure rather than a silent null.
_SCRIPT = b"""import sys
from awsglue.utils import getResolvedOptions
from pyspark.sql import SparkSession
from pyspark.sql.types import StructType, StructField, IntegerType, StringType, DoubleType
from pyspark.sql.functions import count as f_count, sum as f_sum

a = getResolvedOptions(sys.argv, ['INPUT', 'OUTPUT'])
spark = SparkSession.builder.getOrCreate()
schema = StructType([StructField('order_id', IntegerType()),
                     StructField('region', StringType()),
                     StructField('amount', DoubleType())])
src = spark.read.option('header', 'true').option('mode', 'FAILFAST').schema(schema).csv(
    a['INPUT'])
agg = src.groupBy('region').agg(f_count('*').alias('n'), f_sum('amount').alias('total'))
agg.repartition('region').write.mode('overwrite').partitionBy('region').parquet(a['OUTPUT'])
"""


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e",
      "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Glue Spark job writes Hive-partitioned Parquet whose footer types, codec and per-region
    statistics match the input's arithmetic; changing one cell to `not-a-number` fails the run,
    writes nothing to the second prefix and leaves the first run's output unchanged."""
    glue = ctx.client("glue")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    budget = time.monotonic() + _TOTAL_DEADLINE_S

    role = ctx.unique_name("sim2real-behav-b5pqrole-")
    job = ctx.unique_name("sim2real-behav-b5pq-")

    bucket = ctx.unique_name("sim2real-behav-b5pq-").lower()

    try:
        _create_bucket(ctx, s3, bucket)
        ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
        s3.put_bucket_tagging(Bucket=bucket,
                              Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
        s3.put_object(Bucket=bucket, Key="scripts/agg.py", Body=_SCRIPT)
        s3.put_object(Bucket=bucket, Key="input/sales.csv", Body=_CSV)
        s3.put_object(Bucket=bucket, Key="input/bad.csv", Body=_BAD_CSV)

        role_arn = _create_glue_role(ctx, iam, role, bucket)

        glue.create_job(
            Name=job, Role=role_arn,
            Command={"Name": "glueetl", "PythonVersion": "3",
                     "ScriptLocation": f"s3://{bucket}/scripts/agg.py"},
            GlueVersion="4.0", WorkerType="G.1X", NumberOfWorkers=2, MaxRetries=0,
            ExecutionProperty={"MaxConcurrentRuns": 5},
            DefaultArguments={"--TempDir": f"s3://{bucket}/tmp/"},
            Tags={"sim2real": CHECK})
        ctx.on_cleanup(lambda: _retry_delete(lambda: glue.delete_job(JobName=job),
                                             f"glue job {job}"))

        good = _run_job_to_terminal(glue, job, {"--INPUT": f"s3://{bucket}/input/sales.csv",
                                                "--OUTPUT": f"s3://{bucket}/out1/"},
                                    budget=budget)
        assert good["JobRunState"] == "SUCCEEDED", (
            f"the aggregate run ended {good['JobRunState']!r}: {good.get('ErrorMessage')!r}"
        )
        assert good["ExecutionTime"] > 0, (
            f"ExecutionTime was {good['ExecutionTime']!r} on a SUCCEEDED run, so no Spark "
            f"compute was billed and nothing actually executed"
        )

        keys = _list_keys(s3, bucket, "out1/")
        assert keys, "the SUCCEEDED aggregate run wrote nothing under out1/"

        # --- 1. Hive partition directories named by VALUE, not by index or hash.
        dirs = sorted({k.split("/")[1] for k in keys})
        expected_dirs = sorted(f"region={r}" for r in _REGIONS)
        assert dirs == expected_dirs, (
            f"partitionBy('region') produced directories {dirs!r}, expected {expected_dirs!r}; "
            f"an unpartitioned or index-named write fails here. Keys were {keys!r}"
        )

        # --- 2. Nothing outside a partition directory, and every object is a Parquet part.
        stray = [k for k in keys if not k.split("/")[1].startswith("region=")]
        assert stray == [], f"objects written outside a region= directory: {stray!r}"
        non_parquet = [k for k in keys if not k.endswith(".parquet")]
        assert non_parquet == [], (
            f"out1/ holds objects that are not Parquet parts: {non_parquet!r}"
        )
        assert len(keys) == len(_REGIONS), (
            f"expected exactly one part per region ({len(_REGIONS)}), got {len(keys)}: {keys!r}"
        )

        # --- 3. Decode each part's footer with stdlib and grade it against the input arithmetic.
        total_rows = 0
        seen: dict[str, tuple] = {}
        for key in keys:
            region = key.split("/")[1].split("=", 1)[1]
            body = _get_object(s3, bucket, key)
            assert body is not None, f"part {key!r} vanished between list and get"
            assert body[:4] == b"PAR1" and body[-4:] == b"PAR1", (
                f"part {key!r} is not a Parquet file; head/tail were "
                f"{body[:4]!r}/{body[-4:]!r}"
            )
            foot = _parquet_footer(body)

            leaves = [s["name"] for s in foot["schema"] if s.get("type") is not None]
            assert leaves == ["n", "total"], (
                f"part {key!r} file schema leaves are {leaves!r}, expected ['n', 'total'] -- "
                f"Hive partitioning must ENCODE 'region' in the path and REMOVE it from the "
                f"file, and the aggregate column names must survive the shuffle"
            )
            types = {s["name"]: s["type"] for s in foot["schema"] if s.get("type") is not None}
            assert types == {"n": "INT64", "total": "DOUBLE"}, (
                f"part {key!r} physical Parquet types were {types!r}, expected "
                f"{{'n': 'INT64', 'total': 'DOUBLE'}}; a writer that defaults everything to "
                f"BYTE_ARRAY fails here"
            )
            assert foot["created_by"].startswith("parquet-mr"), (
                f"part {key!r} was written by {foot['created_by']!r}, not parquet-mr; Glue 4.0's "
                f"Spark writer stamps the parquet-mr version into the footer"
            )

            assert len(foot["row_groups"]) == 1, (
                f"part {key!r} has {len(foot['row_groups'])} row groups, expected 1"
            )
            group = foot["row_groups"][0]
            assert foot["num_rows"] == 1 and group["num_rows"] == 1, (
                f"part {key!r} reports num_rows {foot['num_rows']!r}/{group['num_rows']!r}; a "
                f"groupBy over one region must produce exactly one aggregated row"
            )
            codecs = sorted({c["codec"] for c in group["columns"]})
            assert codecs == ["SNAPPY"], (
                f"part {key!r} column chunks use codecs {codecs!r}; Glue 4.0's Spark Parquet "
                f"writer compresses with SNAPPY, and an UNCOMPRESSED hand-rolled writer fails "
                f"here"
            )

            stats = {c["path"]: c for c in group["columns"]}
            assert sorted(stats) == ["n", "total"], (
                f"part {key!r} column chunk paths were {sorted(stats)!r}"
            )
            n_col, t_col = stats["n"], stats["total"]
            assert n_col["min_value"] == n_col["max_value"], (
                f"part {key!r} column 'n' has min != max over a single row: "
                f"{n_col['min_value']!r}/{n_col['max_value']!r}"
            )
            n_val = struct.unpack("<q", n_col["min_value"])[0]
            total_val = struct.unpack("<d", t_col["min_value"])[0]
            seen[region] = (n_val, round(total_val, 6))
            total_rows += n_val

        assert seen == _EXPECTED, (
            f"the per-region (count, sum(amount)) read out of the Parquet footers was {seen!r}, "
            f"expected {_EXPECTED!r} -- these numbers are derivable only by shuffling the 5000 "
            f"input rows, and the check computed them from the CSV it uploaded"
        )
        assert total_rows == _ROWS, (
            f"the counts across all partitions sum to {total_rows}, expected {_ROWS}; the "
            f"shuffle lost or duplicated rows"
        )

        # --- 4. The partition column is genuinely absent from the object bytes, not just the
        #        footer schema: neither the column name nor any region value appears anywhere.
        for key in keys:
            region = key.split("/")[1].split("=", 1)[1]
            body = _get_object(s3, bucket, key)
            assert b"region" not in body, (
                f"the literal column name 'region' appears in the bytes of {key!r}, so the "
                f"partition column was written into the file instead of the path"
            )
            assert region.encode() not in body, (
                f"the partition value {region!r} appears in the bytes of {key!r}; Hive "
                f"partitioning encodes it in the directory name only"
            )

        assert _get_object(s3, bucket, "input/sales.csv") == _CSV, (
            "the input object was modified by the run; the source must be read-only to the job"
        )

        # --- 5. Negative arm: one malformed cell, everything else identical.
        bad = _run_job_to_terminal(glue, job, {"--INPUT": f"s3://{bucket}/input/bad.csv",
                                               "--OUTPUT": f"s3://{bucket}/out2/"},
                                   budget=budget)
        assert bad["JobRunState"] == "FAILED", (
            f"a CSV whose 'amount' cell is 'not-a-number', read under an explicit DoubleType "
            f"schema in FAILFAST mode, ended {bad['JobRunState']!r} instead of FAILED; "
            f"ErrorMessage was {bad.get('ErrorMessage')!r}"
        )
        message = bad.get("ErrorMessage") or ""
        assert "not-a-number" in message, (
            f"the failed run's ErrorMessage does not name the offending value: {message!r}; the "
            f"failure must be attributed to the malformed cell, not to something else"
        )
        assert bad["ExecutionTime"] > 0, (
            f"the failed run's ExecutionTime was {bad['ExecutionTime']!r}; the failure must come "
            f"from Spark actually reading the data, not from a control-plane pre-check"
        )

        # effect-absent
        out2 = _list_keys(s3, bucket, "out2/")
        assert out2 == [], (
            f"the FAILED run left objects under out2/: {out2!r}; a run that could not parse its "
            f"input must publish nothing"
        )
        # positive control, unchanged
        assert _list_keys(s3, bucket, "out1/") == keys, (
            f"the failed run disturbed the successful run's output; out1/ now holds "
            f"{_list_keys(s3, bucket, 'out1/')!r}, was {keys!r}"
        )
        assert (glue.get_job(JobName=job)["Job"]["Command"]
                == {"Name": "glueetl", "PythonVersion": "3",
                    "ScriptLocation": f"s3://{bucket}/scripts/agg.py"}), (
            f"the two runs must differ only in their Arguments; the job Command is "
            f"{glue.get_job(JobName=job)['Job']['Command']!r}"
        )
    except BaseException as primary:
        # Verified inline teardown under the check's own budget. ctx.on_cleanup remains as the
        # failure-path net, but the engine runs that whole chain on a daemon thread joined with
        # a 60 s timeout and NEVER lets it affect the verdict, so a teardown that ran only
        # there could leak while the check still reported PASS.
        try:
            _teardown(glue, s3, iam, jobs=[job], bucket=bucket, roles=[role])
        except Exception as td:  # noqa: BLE001 - the body's failure stays the verdict
            primary.add_note(f"inline teardown also failed: {td!r}")
        raise
    else:
        _teardown(glue, s3, iam, jobs=[job], bucket=bucket, roles=[role])


# ===== stdlib Parquet footer reader (Thrift compact protocol) ===================
#
# pyarrow is not importable on the runner, so the footer is decoded here; nothing below
# is conditional on an import.

_PQ_TYPE = {0: "BOOLEAN", 1: "INT32", 2: "INT64", 3: "INT96", 4: "FLOAT", 5: "DOUBLE",
            6: "BYTE_ARRAY", 7: "FIXED_LEN_BYTE_ARRAY"}
_PQ_CODEC = {0: "UNCOMPRESSED", 1: "SNAPPY", 2: "GZIP", 3: "LZO", 4: "BROTLI", 5: "LZ4",
             6: "ZSTD", 7: "LZ4_RAW"}


class _Thrift:
    """Just enough Thrift compact protocol to read a Parquet FileMetaData struct."""

    def __init__(self, buf: bytes) -> None:
        self.buf = buf
        self.pos = 0

    def _u8(self) -> int:
        value = self.buf[self.pos]
        self.pos += 1
        return value

    def _varint(self) -> int:
        result = shift = 0
        while True:
            byte = self._u8()
            result |= (byte & 0x7F) << shift
            if not byte & 0x80:
                return result
            shift += 7

    def _zigzag(self) -> int:
        n = self._varint()
        return (n >> 1) ^ -(n & 1)

    def value(self, kind: int):
        if kind == 1:
            return True
        if kind == 2:
            return False
        if kind == 3:
            return self._u8()
        if kind in (4, 5, 6):
            return self._zigzag()
        if kind == 7:
            out = struct.unpack_from("<d", self.buf, self.pos)[0]
            self.pos += 8
            return out
        if kind == 8:
            size = self._varint()
            out = self.buf[self.pos:self.pos + size]
            self.pos += size
            return out
        if kind in (9, 10):
            header = self._u8()
            size, elem = header >> 4, header & 0x0F
            if size == 15:
                size = self._varint()
            return [self.value(elem) for _ in range(size)]
        if kind == 11:
            size = self._varint()
            if size == 0:
                return {}
            header = self._u8()
            key_kind, val_kind = header >> 4, header & 0x0F
            return {self.value(key_kind): self.value(val_kind) for _ in range(size)}
        if kind == 12:
            return self.struct()
        raise AssertionError(f"unsupported Thrift compact type id {kind}")

    def struct(self) -> dict:
        out: dict = {}
        field = 0
        while True:
            header = self._u8()
            if header == 0:
                return out
            kind, delta = header & 0x0F, header >> 4
            field = self._zigzag() if delta == 0 else field + delta
            out[field] = self.value(kind)


def _parquet_footer(body: bytes) -> dict:
    """Decode a Parquet file's FileMetaData. Stdlib only -- no pyarrow, no fallback."""
    assert len(body) > 12 and body[:4] == b"PAR1" and body[-4:] == b"PAR1", (
        f"not a Parquet file: {len(body)} bytes, head {body[:4]!r} tail {body[-4:]!r}"
    )
    footer_len = struct.unpack_from("<I", body, len(body) - 8)[0]
    start = len(body) - 8 - footer_len
    assert start >= 4, f"footer length {footer_len} does not fit in {len(body)} bytes"
    meta = _Thrift(body[start:len(body) - 8]).struct()

    schema = [{"name": el.get(4, b"").decode(),
               "type": _PQ_TYPE.get(el[1]) if 1 in el else None,
               "num_children": el.get(5)} for el in meta.get(2, [])]
    row_groups = []
    for group in meta.get(4, []):
        columns = []
        for chunk in group.get(1, []):
            column = chunk.get(3, {})
            stats = column.get(12) or {}
            columns.append({"path": ".".join(p.decode() for p in column.get(3, [])),
                            "type": _PQ_TYPE.get(column.get(1)),
                            "codec": _PQ_CODEC.get(column.get(4)),
                            "num_values": column.get(5),
                            "min_value": stats.get(6),
                            "max_value": stats.get(5)})
        row_groups.append({"num_rows": group.get(3), "columns": columns})
    return {"version": meta.get(1), "num_rows": meta.get(3), "schema": schema,
            "row_groups": row_groups,
            "created_by": (meta.get(6) or b"").decode(errors="replace")}


# ===== inlined AWS plumbing (self-contained) ===========================================

def _create_bucket(ctx, s3, bucket: str) -> None:
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket,
                         CreateBucketConfiguration={"LocationConstraint": ctx.region})


def _create_glue_role(ctx, iam, role: str, bucket: str) -> str:
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow",
                       "Principal": {"Service": "glue.amazonaws.com"},
                       "Action": "sts:AssumeRole"}]})
    arn = iam.create_role(RoleName=role, AssumeRolePolicyDocument=trust,
                          Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: iam.delete_role(RoleName=role),
                                         f"iam role {role}"))
    managed = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    iam.attach_role_policy(RoleName=role, PolicyArn=managed)
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: iam.detach_role_policy(RoleName=role, PolicyArn=managed),
        f"detach {managed} from {role}"))
    iam.put_role_policy(RoleName=role, PolicyName="sim2real-s3", PolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow",
                       "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
                       "Resource": f"arn:aws:s3:::{bucket}/*"},
                      {"Effect": "Allow",
                       "Action": ["s3:ListBucket", "s3:GetBucketLocation"],
                       "Resource": f"arn:aws:s3:::{bucket}"}]}))
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: iam.delete_role_policy(RoleName=role, PolicyName="sim2real-s3"),
        f"inline policy on {role}"))
    # IAM propagation exposes no condition to poll, so no fixed pre-sleep belongs here either:
    # _run_job_to_terminal already carries the bounded retry on the "should be given assume
    # role permissions" run failure, with a deadline and a stated reason.
    return arn


def _run_job_to_terminal(glue, job: str, arguments: dict, *, budget: float) -> dict:
    """Start the job and poll to a terminal state, retrying the IAM-propagation failure.

    Glue reports "Role ... should be given assume role permissions for Glue Service" as a
    FAILED job *run* a few seconds in, not as a StartJobRun error, and no API reports that
    the role has become assumable -- so the bounded retry has to be on the terminal state.
    ``budget`` is the whole check's monotonic deadline, shared by every run.
    """
    from botocore.exceptions import ClientError

    record: dict = {}
    while time.monotonic() < budget:
        try:
            run_id = glue.start_job_run(JobName=job, Arguments=arguments)["JobRunId"]
        except ClientError as err:
            if err.response["Error"]["Code"] != "ConcurrentRunsExceededException":
                raise
            time.sleep(5)
            continue
        while time.monotonic() < budget:
            record = glue.get_job_run(JobName=job, RunId=run_id)["JobRun"]
            if record["JobRunState"] in ("SUCCEEDED", "FAILED", "STOPPED", "ERROR",
                                         "TIMEOUT"):
                break
            time.sleep(2)
        if record.get("JobRunState") != "FAILED":
            return record
        if "assume role permissions" not in (record.get("ErrorMessage") or ""):
            return record
        time.sleep(2)
    raise AssertionError(
        f"job {job!r} did not reach a terminal run state inside the check's "
        f"{_TOTAL_DEADLINE_S}s budget; last record was {record!r}")


def _teardown(glue, s3, iam, *, jobs, bucket, roles) -> None:
    """Delete everything and poll each API until it says the resource is gone.

    Raises on anything but the resource already being gone. Children before parents: role
    policies before the role, objects before the bucket.
    """
    from botocore.exceptions import ClientError

    def verify(label: str, delete: Callable[[], Any], probe: Callable[[], Any],
               gone_codes: tuple, *, timeout_s: float = 120.0) -> None:
        try:
            delete()
        except ClientError as err:
            if err.response["Error"]["Code"] not in gone_codes:
                raise
        deadline = time.monotonic() + timeout_s
        while True:
            try:
                probe()
            except ClientError as err:
                if err.response["Error"]["Code"] in gone_codes:
                    return
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(f"the inline teardown found {label} still present "
                                     f"{timeout_s}s after delete")
            time.sleep(2)

    for name in jobs:
        verify(f"glue job {name}", lambda n=name: glue.delete_job(JobName=n),
               lambda n=name: glue.get_job(JobName=n), ("EntityNotFoundException",))
    for role in roles:
        try:
            for policy in iam.list_role_policies(RoleName=role)["PolicyNames"]:
                iam.delete_role_policy(RoleName=role, PolicyName=policy)
            for attached in iam.list_attached_role_policies(
                    RoleName=role)["AttachedPolicies"]:
                iam.detach_role_policy(RoleName=role, PolicyArn=attached["PolicyArn"])
        except ClientError as err:
            if err.response["Error"]["Code"] != "NoSuchEntity":
                raise
        verify(f"iam role {role}", lambda r=role: iam.delete_role(RoleName=r),
               lambda r=role: iam.get_role(RoleName=r), ("NoSuchEntity",))
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            objects = [{"Key": o["Key"], "VersionId": o["VersionId"]}
                       for o in page.get("Versions", []) + page.get("DeleteMarkers", [])]
            if objects:
                s3.delete_objects(Bucket=bucket, Delete={"Objects": objects})
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchBucket":
            raise
    verify(f"s3 bucket {bucket}", lambda: s3.delete_bucket(Bucket=bucket),
           lambda: s3.head_bucket(Bucket=bucket), ("404", "NoSuchBucket"))


def _get_object(s3, bucket: str, key: str):
    from botocore.exceptions import ClientError
    try:
        return s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    except ClientError as err:
        if err.response["Error"]["Code"] == "NoSuchKey":
            return None
        raise


def _list_keys(s3, bucket: str, prefix: str) -> list:
    keys = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        keys.extend(o["Key"] for o in page.get("Contents", []))
    return sorted(keys)


def _retry_delete(fn: Callable[[], Any], label: str, *, timeout_s: float = 120.0) -> None:
    """Delete with a bounded retry, because ctx.on_cleanup SWALLOWS teardown exceptions:
    a throttled or dependency-blocked delete would leak silently while the check passes."""
    from botocore.exceptions import ClientError

    gone = ("EntityNotFoundException", "NoSuchEntity", "NoSuchBucket",
            "ResourceNotFoundException", "404")
    transient = ("ThrottlingException", "Throttling", "TooManyRequestsException",
                 "OperationTimeoutException", "ConcurrentModificationException",
                 "DeleteConflict", "InvalidInputException", "RequestLimitExceeded",
                 "ConcurrentRunsExceededException")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in gone:
                return
            if code not in transient or time.monotonic() >= deadline:
                raise RuntimeError(f"{label}: {code}: {err}") from err
            time.sleep(3)
        except Exception as exc:  # noqa: BLE001 - re-raised
            raise RuntimeError(f"{label}: {type(exc).__name__}: {exc}") from exc


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    """The ctx.on_cleanup failure-path net. The inline teardown in run()'s `finally` normally
    got here first, so an already-absent bucket is the expected case, not a leak."""
    from botocore.exceptions import ClientError

    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            objects = [{"Key": o["Key"], "VersionId": o["VersionId"]}
                       for o in page.get("Versions", []) + page.get("DeleteMarkers", [])]
            if objects:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objects}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchBucket":
            raise
        return
    _retry_delete(lambda: s3.delete_bucket(Bucket=bucket), f"s3 bucket {bucket}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
