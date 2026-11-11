"""obs-s3-2-object-data-events-record-success-missing-key-and-denied-calls."""
from __future__ import annotations

import gzip
import io
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "obs-s3-2-object-data-events-record-success-missing-key-and-denied-calls"
GROUP = "eventing"
SERVICES = ["cloudtrail", "s3"]

DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

# Data events are documented as delivered roughly every 5 minutes; 600 s is 2x that.
_DELIVERY_BUDGET_S = 600.0
_IAM_BUDGET_S = 90.0
_CLEANUP_BUDGET_S = 240.0
_ROUND_INTERVAL_S = 30.0  # spacing between repeated call rounds, not a poll interval
_POLL_INTERVAL_S = 2.0
_MAX_ROUNDS = 20
_ROLE_SESSION = "sim2real-ctdeny"
_NO_SUCH_KEY_MESSAGE = "The specified key does not exist."
_HEAD_NOT_FOUND_MESSAGE = "Not Found"
_DENIED_MESSAGE = (
    "User: {session} is not authorized to perform: {action} on resource: \"{resource}\" with an "
    "explicit deny in a resource-based policy"
)

# ===== helpers =====


def _error(fn):
    """(code, message) of the error fn raised. Raises if fn SUCCEEDS: an accepted call is the
    strongest signal there is and must never be confused with a code."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected the call to be rejected, but it succeeded")


def _create_bucket(ctx, prefix):
    s3 = ctx.client("s3")
    name = ctx.unique_name(prefix)
    kw = {"Bucket": name}
    if ctx.region != "us-east-1":
        kw["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kw)
    ctx.on_cleanup(lambda: _drain_and_delete_bucket(s3, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return name


def _drain_and_delete_bucket(s3, bucket):
    """RAISES on a deadline miss so a leak is visible rather than silent: the trail can still
    write a final log file after StopLogging/DeleteTrail."""
    deadline = time.monotonic() + _CLEANUP_BUDGET_S
    while True:
        keys = []
        token = None
        while True:
            kw = {"Bucket": bucket, "MaxKeys": 1000}
            if token:
                kw["ContinuationToken"] = token
            try:
                page = s3.list_objects_v2(**kw)
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") == "NoSuchBucket":
                    return
                raise
            keys.extend(o["Key"] for o in page.get("Contents", []))
            token = page.get("NextContinuationToken")
            if not token:
                break
        for i in range(0, len(keys), 1000):
            s3.delete_objects(
                Bucket=bucket, Delete={"Objects": [{"Key": k} for k in keys[i : i + 1000]]}
            )
        try:
            s3.delete_bucket(Bucket=bucket)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "NoSuchBucket":
                return
            if code != "BucketNotEmpty":
                raise
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"bucket {bucket} still not empty after {_CLEANUP_BUDGET_S:.0f}s"
            )
        time.sleep(10.0)


def _attach_trail_policy(s3, bucket, account_id):
    s3.put_bucket_policy(
        Bucket=bucket,
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "cloudtrail.amazonaws.com"},
                        "Action": "s3:GetBucketAcl",
                        "Resource": f"arn:aws:s3:::{bucket}",
                    },
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "cloudtrail.amazonaws.com"},
                        "Action": "s3:PutObject",
                        "Resource": f"arn:aws:s3:::{bucket}/AWSLogs/{account_id}/*",
                        "Condition": {
                            "StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}
                        },
                    },
                ],
            }
        ),
    )


def _delivered_records(s3, bucket):
    """Every record in every delivered gzipped log file under AWSLogs/."""
    keys = []
    token = None
    while True:
        kw = {"Bucket": bucket, "Prefix": "AWSLogs/", "MaxKeys": 1000}
        if token:
            kw["ContinuationToken"] = token
        page = s3.list_objects_v2(**kw)
        keys.extend(o["Key"] for o in page.get("Contents", []) if o["Key"].endswith(".json.gz"))
        token = page.get("NextContinuationToken")
        if not token:
            break
    out = []
    for key in keys:
        body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
        if not body:
            continue
        with gzip.GzipFile(fileobj=io.BytesIO(body)) as fh:
            out.extend(json.loads(fh.read().decode("utf-8")).get("Records", []))
    return out


def _find(records, event_name, bucket, key):
    """Matching records, de-duplicated by eventID (a log file may be re-read across polls)."""
    out = {}
    for r in records:
        params = r.get("requestParameters") or {}
        if (r.get("eventName") == event_name and params.get("bucketName") == bucket
                and params.get("key") == key):
            out.setdefault(r.get("eventID"), r)
    return list(out.values())


def _stop_logging_quietly(ct, trail_arn):
    try:
        ct.stop_logging(Name=trail_arn)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "TrailNotFoundException":
            raise


def _delete_role(iam, role_name, policy_name):
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


def _assume_with_retry(sts, role_arn, session_name):
    """IAM propagation exposes no condition to poll: retry the first use of the trust policy."""
    deadline = time.monotonic() + _IAM_BUDGET_S
    while True:
        try:
            return sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)["Credentials"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "AccessDenied":
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(5.0)


def _put_with_retry(s3, bucket, key, body):
    """First use of the role's identity policy: bounded AccessDenied retry (propagation)."""
    deadline = time.monotonic() + _IAM_BUDGET_S
    while True:
        try:
            return s3.put_object(Bucket=bucket, Key=key, Body=body)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "AccessDenied":
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(5.0)


def _assert_object_record(rec, *, label, event_name, bucket, key, read_only, error_code,
                          error_message=None):
    assert rec.get("eventSource") == "s3.amazonaws.com", (
        f"{label}: eventSource expected 's3.amazonaws.com', actual {rec.get('eventSource')!r}"
    )
    assert rec.get("eventCategory") == "Data", (
        f"{label}: eventCategory expected 'Data', actual {rec.get('eventCategory')!r}"
    )
    assert rec.get("managementEvent") is False, (
        f"{label}: managementEvent expected False, actual {rec.get('managementEvent')!r}"
    )
    assert rec.get("eventName") == event_name, (
        f"{label}: eventName expected {event_name!r}, actual {rec.get('eventName')!r}"
    )
    assert rec.get("readOnly") is read_only, (
        f"{label}: readOnly expected {read_only!r}, actual {rec.get('readOnly')!r}"
    )
    params = rec.get("requestParameters") or {}
    assert params.get("bucketName") == bucket, (
        f"{label}: requestParameters.bucketName expected {bucket!r}, actual "
        f"{params.get('bucketName')!r}"
    )
    assert params.get("key") == key, (
        f"{label}: requestParameters.key expected {key!r}, actual {params.get('key')!r}"
    )
    want_arn = f"arn:aws:s3:::{bucket}/{key}"
    objs = [r for r in rec.get("resources") or [] if r.get("type") == "AWS::S3::Object"]
    assert [r.get("ARN") for r in objs] == [want_arn], (
        f"{label}: resources[] must hold exactly one AWS::S3::Object entry with ARN {want_arn!r}, "
        f"actual {rec.get('resources')!r}"
    )
    if error_code is None:
        assert "errorCode" not in rec, (
            f"{label}: a successful call must carry NO errorCode field, actual "
            f"{rec.get('errorCode')!r}"
        )
        assert "errorMessage" not in rec, (
            f"{label}: a successful call must carry NO errorMessage field, actual "
            f"{rec.get('errorMessage')!r}"
        )
    else:
        assert rec.get("errorCode") == error_code, (
            f"{label}: errorCode expected {error_code!r}, actual {rec.get('errorCode')!r}"
        )
        assert rec.get("errorMessage") == error_message, (
            f"{label}: errorMessage expected {error_message!r}, actual {rec.get('errorMessage')!r}"
        )


@tags(
    "concern:data-plane",
    "concern:eventing",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "axis:rejection",
    "cap:c7",
)
def run(ctx) -> None:
    """A trail logging S3 object data events records a successful PutObject and GetObject, a
    NoSuchKey GetObject and two bucket-policy-denied calls, each with the right classification,
    request parameters, object ARN and error fields; the role's allowed write is the control.
    """
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    s3 = ctx.client("s3")
    ct = ctx.client("cloudtrail")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    payload = b"sim2real-cloudtrail-s3-data-event"

    # Cleanup ordering: buckets are registered FIRST so LIFO deletes them LAST, after the trail
    # has stopped writing into the log bucket.
    log_bucket = _create_bucket(ctx, "sim2real-xsvc-ctlog-")
    _attach_trail_policy(s3, log_bucket, account_id)
    data_bucket = _create_bucket(ctx, "sim2real-xsvc-ctdata-")

    # ---- the role that the bucket policy denies ----------------------------------------------
    role_name = ctx.unique_name("sim2real-xsvc-ctdeny-")
    policy_name = "sim2real-s3-access"
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
        Description="sim2real-xsvc cloudtrail__s3 denied principal",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_name, policy_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject", "s3:PutObject"],
                        "Resource": f"arn:aws:s3:::{data_bucket}/*",
                    }
                ],
            }
        ),
    )
    s3.put_bucket_policy(
        Bucket=data_bucket,
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "DenyRoleOnDeniedPrefix",
                        "Effect": "Deny",
                        # Principal "*" + aws:PrincipalArn rather than Principal {"AWS": role_arn}:
                        # measured, S3 rejects a seconds-old role as a Principal with
                        # MalformedPolicy "Invalid principal in policy" until IAM propagates.
                        "Principal": "*",
                        "Action": ["s3:GetObject", "s3:PutObject"],
                        "Resource": f"arn:aws:s3:::{data_bucket}/denied/*",
                        "Condition": {"ArnEquals": {"aws:PrincipalArn": role_arn}},
                    }
                ],
            }
        ),
    )

    # ---- the trail: S3 object data events for the data bucket only ---------------------------
    trail_name = ctx.unique_name("sim2real-xsvc-ct-")
    trail_arn = ct.create_trail(
        Name=trail_name,
        S3BucketName=log_bucket,
        IsMultiRegionTrail=False,
        IncludeGlobalServiceEvents=False,
        TagsList=[{"Key": "sim2real", "Value": CHECK}],
    )["TrailARN"]
    ctx.on_cleanup(lambda: ct.delete_trail(Name=trail_arn))
    selectors = [
        {
            "Name": "s3-objects-in-data-bucket",
            "FieldSelectors": [
                {"Field": "eventCategory", "Equals": ["Data"]},
                {"Field": "resources.type", "Equals": ["AWS::S3::Object"]},
                {"Field": "resources.ARN", "StartsWith": [f"arn:aws:s3:::{data_bucket}/"]},
            ],
        }
    ]
    ct.put_event_selectors(TrailName=trail_arn, AdvancedEventSelectors=selectors)
    ct.start_logging(Name=trail_arn)
    ctx.on_cleanup(lambda: _stop_logging_quietly(ct, trail_arn))
    is_logging = ct.get_trail_status(Name=trail_arn).get("IsLogging")
    assert is_logging is True, f"trail must be logging before the data plane runs, got {is_logging!r}"

    # The role session. Assumed now so the trust-policy propagation wait overlaps nothing.
    role_creds = _assume_with_retry(sts, role_arn, _ROLE_SESSION)
    s3_role = ctx.client(
        "s3",
        creds={
            "aws_access_key_id": role_creds["AccessKeyId"],
            "aws_secret_access_key": role_creds["SecretAccessKey"],
            "aws_session_token": role_creds["SessionToken"],
        },
    )

    # ---- the data plane ------------------------------------------------------------------------
    k = ctx.unique_name("k")
    role_session_arn = f"arn:aws:sts::{account_id}:assumed-role/{role_name}/{_ROLE_SESSION}"

    def _denied_message(action, key):
        return _DENIED_MESSAGE.format(
            session=role_session_arn, action=action, resource=f"arn:aws:s3:::{data_bucket}/{key}"
        )

    # Positive control for the role, once: its identity policy is effective (propagated) outside
    # the denied prefix, so every AccessDenied below is the bucket policy's explicit Deny.
    _put_with_retry(s3_role, data_bucket, f"allowed/{k}", payload)

    def _round(r):
        """One full call sequence on fresh keys; returns label -> (eventName, key)."""
        keys = {
            "ok": f"obj/{k}-{r}",
            "missing": f"obj/missing-{k}-{r}",
            "denied_get": f"denied/get-{k}-{r}",
            "denied_put": f"denied/put-{k}-{r}",
            "barrier": f"obj/barrier-{k}-{r}",
        }
        s3.put_object(Bucket=data_bucket, Key=keys["ok"], Body=payload)
        got = s3.get_object(Bucket=data_bucket, Key=keys["ok"])["Body"].read()
        assert got == payload, f"GetObject on the written key returned {got!r}, expected {payload!r}"
        code, message = _error(lambda: s3.get_object(Bucket=data_bucket, Key=keys["missing"]))
        assert code == "NoSuchKey", (
            f"GetObject on a missing key: expected 'NoSuchKey', actual {code!r}"
        )
        assert message == _NO_SUCH_KEY_MESSAGE, (
            f"GetObject on a missing key: expected message {_NO_SUCH_KEY_MESSAGE!r}, actual "
            f"{message!r}"
        )
        # The denied GetObject targets an object that EXISTS, so its refusal cannot be a
        # disguised NoSuchKey. The caller (not the role) writes it.
        s3.put_object(Bucket=data_bucket, Key=keys["denied_get"], Body=payload)
        code, message = _error(
            lambda: s3_role.get_object(Bucket=data_bucket, Key=keys["denied_get"])
        )
        assert code == "AccessDenied", (
            f"role GetObject under the bucket-policy Deny: expected 'AccessDenied', actual {code!r}"
        )
        want = _denied_message("s3:GetObject", keys["denied_get"])
        assert message == want, (
            f"role GetObject under the bucket-policy Deny: expected message {want!r}, actual "
            f"{message!r}"
        )
        code, message = _error(
            lambda: s3_role.put_object(Bucket=data_bucket, Key=keys["denied_put"], Body=payload)
        )
        assert code == "AccessDenied", (
            f"role PutObject under the bucket-policy Deny: expected 'AccessDenied', actual {code!r}"
        )
        want = _denied_message("s3:PutObject", keys["denied_put"])
        assert message == want, (
            f"role PutObject under the bucket-policy Deny: expected message {want!r}, actual "
            f"{message!r}"
        )
        # Effect absent: the denied write did not land.
        code, message = _error(lambda: s3.head_object(Bucket=data_bucket, Key=keys["denied_put"]))
        assert (code, message) == ("404", _HEAD_NOT_FOUND_MESSAGE), (
            f"the denied PutObject must not create the object; HeadObject gave {code!r} "
            f"{message!r}, expected '404' {_HEAD_NOT_FOUND_MESSAGE!r}"
        )
        # The structural barrier: issued LAST in the round.
        s3.put_object(Bucket=data_bucket, Key=keys["barrier"], Body=payload)
        return keys, {
            "put-ok": ("PutObject", keys["ok"]),
            "get-ok": ("GetObject", keys["ok"]),
            "get-missing": ("GetObject", keys["missing"]),
            "get-denied": ("GetObject", keys["denied_get"]),
            "put-denied": ("PutObject", keys["denied_put"]),
            "barrier": ("PutObject", keys["barrier"]),
        }

    # Calls issued within seconds of StartLogging may never be delivered, and nothing reports when
    # a fresh trail starts capturing, so the sequence is REPEATED on fresh keys every round and the
    # first round whose six records (barrier included) all arrive is the one graded.
    rounds = []
    deadline = time.monotonic() + _DELIVERY_BUDGET_S
    graded = None
    records = []
    next_round = time.monotonic()
    while graded is None:
        if len(rounds) < _MAX_ROUNDS and time.monotonic() >= next_round:
            rounds.append(_round(len(rounds)))
            next_round = time.monotonic() + _ROUND_INTERVAL_S
        time.sleep(_POLL_INTERVAL_S)
        records = _delivered_records(s3, log_bucket)
        for keys, wanted in rounds:
            found = {label: _find(records, en, data_bucket, key)
                     for label, (en, key) in wanted.items()}
            if all(found.values()):
                graded = (keys, wanted, found)
                break
        if graded is None and time.monotonic() >= deadline:
            raise AssertionError(
                f"{DATAPLANE_MARKER}: within {_DELIVERY_BUDGET_S:.0f}s, over {len(rounds)} rounds of "
                f"the call sequence, the trail delivered {len(records)} records to "
                f"s3://{log_bucket} and no round had all six of its records delivered"
            )
    keys, wanted, found = graded

    for label, recs in found.items():
        assert len(recs) == 1, (
            f"{label}: expected exactly one delivered record for {wanted[label]!r}, actual "
            f"{len(recs)}"
        )

    _assert_object_record(found["put-ok"][0], label="put-ok", event_name="PutObject",
                          bucket=data_bucket, key=keys["ok"], read_only=False, error_code=None)
    _assert_object_record(found["get-ok"][0], label="get-ok", event_name="GetObject",
                          bucket=data_bucket, key=keys["ok"], read_only=True, error_code=None)
    _assert_object_record(found["barrier"][0], label="barrier", event_name="PutObject",
                          bucket=data_bucket, key=keys["barrier"], read_only=False,
                          error_code=None)
    _assert_object_record(found["get-missing"][0], label="get-missing", event_name="GetObject",
                          bucket=data_bucket, key=keys["missing"], read_only=True,
                          error_code="NoSuchKey", error_message=_NO_SUCH_KEY_MESSAGE)
    _assert_object_record(found["get-denied"][0], label="get-denied", event_name="GetObject",
                          bucket=data_bucket, key=keys["denied_get"], read_only=True,
                          error_code="AccessDenied",
                          error_message=_denied_message("s3:GetObject", keys["denied_get"]))
    _assert_object_record(found["put-denied"][0], label="put-denied", event_name="PutObject",
                          bucket=data_bucket, key=keys["denied_put"], read_only=False,
                          error_code="AccessDenied",
                          error_message=_denied_message("s3:PutObject", keys["denied_put"]))

    # The denied records name the ROLE as the caller; the others name the leased principal.
    for label in ("get-denied", "put-denied"):
        ident = found[label][0].get("userIdentity") or {}
        issuer = ((ident.get("sessionContext") or {}).get("sessionIssuer") or {}).get("arn")
        assert ident.get("type") == "AssumedRole" and issuer == role_arn, (
            f"{label}: userIdentity must be the denied role session (type 'AssumedRole', issuer "
            f"{role_arn!r}), actual type {ident.get('type')!r} issuer {issuer!r}"
        )
    for label in ("put-ok", "get-ok", "get-missing"):
        ident = found[label][0].get("userIdentity") or {}
        assert ident.get("type") != "AssumedRole" or (
            ((ident.get("sessionContext") or {}).get("sessionIssuer") or {}).get("arn") != role_arn
        ), f"{label}: was attributed to the denied role, actual userIdentity {ident!r}"
        assert ident.get("accountId") == account_id, (
            f"{label}: userIdentity.accountId expected {account_id!r}, actual "
            f"{ident.get('accountId')!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
