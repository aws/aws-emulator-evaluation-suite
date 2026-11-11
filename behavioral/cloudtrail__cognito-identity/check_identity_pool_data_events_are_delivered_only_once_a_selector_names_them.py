"""identity-pool-data-events-are-delivered-only-once-a-selector-names-them."""

from __future__ import annotations

import datetime
import gzip
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "identity-pool-data-events-are-delivered-only-once-a-selector-names-them"
GROUP = "eventing"
SERVICES = ["cloudtrail", "cognito-identity"]

# Marks a failure where no log file is ever delivered, so it reads as a fidelity failure rather
# than a connection error.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

_REDACTED = "HIDDEN_DUE_TO_SECURITY_REASONS"
_DATA_EVENT_NAMES = ("GetId", "GetOpenIdToken")
_POOL_RESOURCE_TYPE = "AWS::Cognito::IdentityPool"  # NOT AWS::CognitoIdentity::...

# A fresh trail delivers nothing for calls made in its first moments, and a new selector applies
# only after a lag, so both phases repeat their calls every round until one round lands, polling
# the bucket in between. Warm-up plus delivery plus the absence hold stay under the suite's 1800s
# ceiling.
_WARM_BUDGET_S = 540.0
_DELIVERY_BUDGET_S = 660.0
_ROUND_INTERVAL_S = 20.0
_DELIVERY_POLL_S = 2.0
_ABSENCE_MULTIPLE = 1.0  # of the MEASURED delivery latency L
# Deliberately DECOUPLED from L (unlike the delivery budget above): by the time the marker is
# FOUND, pool B's delivered records and the marker itself are already confirmed landed, and pool
# A's withheld calls happened even earlier in wall-clock terms -- so if they had been mistakenly
# captured, they would already be in the same batch(es) pool B's records arrived in. A small fixed
# hold is the safety margin against a straggling batch, not a second full delivery wait; scaling it
# with L would blow the suite's 1800s ceiling once L itself needed raising.
_ABSENCE_CEILING_S = 150.0
_PAGE_CEILING = 40

# ===== helpers =====
# Every swallow is narrowed to ClientError.


def _call(fn, retry_codes=(
    "ThrottlingException",
    "TooManyRequestsException",
    "MaximumNumberOfTrailsExceededException",
    "ConflictException",
    "InsufficientS3BucketPolicyException",
), attempts=7):
    """Invoke fn(), retrying transient control-plane errors. Raises the last error."""
    last = None
    for i in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in retry_codes and i < attempts - 1:
                last = exc
                time.sleep(2.0 * (i + 1))
                continue
            raise
    raise last


def _create_trail_bucket(s3, bucket, region, account_id):
    kwargs = {"Bucket": bucket}
    # us-east-1 is S3's own API quirk, not a pin on THIS bucket's location: CreateBucket rejects
    # an explicit LocationConstraint of us-east-1, so the region literal here selects the request
    # shape, not where the bucket lives -- ctx.region (the real target) is what is passed through.
    if region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": region}
    try:
        s3.create_bucket(**kwargs)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in (
            "BucketAlreadyOwnedByYou", "BucketAlreadyExists",
        ):
            raise
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]}
    )
    # The AWSCloudTrailAclCheck (GetBucketAcl) statement stays -- CreateTrail's own synchronous
    # bucket-policy validator rejects the trail with InsufficientS3BucketPolicyException if it is
    # absent. AWSCloudTrailWrite carries NO `s3:x-amz-acl` condition: CreateBucket with no
    # explicit ObjectOwnership defaults to "Bucket owner enforced" (ACLs disabled) for every
    # bucket created since April 2023, and CloudTrail's docs say to drop the ACL condition for
    # that Object Ownership setting
    # (https://docs.aws.amazon.com/awscloudtrail/latest/userguide/create-s3-bucket-policy-for-cloudtrail.html).
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AWSCloudTrailAclCheck",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Resource": f"arn:aws:s3:::{bucket}",
            },
            {
                "Sid": "AWSCloudTrailWrite",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{bucket}/AWSLogs/{account_id}/*",
            },
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))


def _purge_bucket_once(s3, bucket):
    removed = 0
    for paginator_name, list_key, id_key in (
        ("list_objects_v2", "Contents", None),
        ("list_object_versions", "Versions", "VersionId"),
        ("list_object_versions", "DeleteMarkers", "VersionId"),
    ):
        paginator = s3.get_paginator(paginator_name)
        try:
            for page in paginator.paginate(Bucket=bucket):
                entries = page.get(list_key, [])
                if not entries:
                    continue
                objects = []
                for entry in entries:
                    item = {"Key": entry["Key"]}
                    if id_key and entry.get(id_key):
                        item["VersionId"] = entry[id_key]
                    objects.append(item)
                s3.delete_objects(Bucket=bucket, Delete={"Objects": objects})
                removed += len(objects)
        except ClientError:
            continue
    return removed


def _drain_and_delete_bucket(s3, bucket, *, attempts=8, delay_s=15.0):
    """Empty and delete the log bucket, retrying because CloudTrail may still be writing.
    RAISES on a deadline miss so a leaked billable bucket is visible."""
    last = None
    for attempt in range(attempts):
        _purge_bucket_once(s3, bucket)
        try:
            s3.delete_bucket(Bucket=bucket)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "NoSuchBucket":
                return
            last = exc
            if attempt < attempts - 1:
                time.sleep(delay_s)
    raise AssertionError(
        f"could not delete trail log bucket {bucket} after {attempts} attempts; a billable S3 "
        f"bucket and its CloudTrail log files have been LEAKED. Last error: {last}"
    )


def _delete_trail_idempotent(ct, name):
    for fn in (lambda: ct.stop_logging(Name=name), lambda: ct.delete_trail(Name=name)):
        try:
            _call(fn)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "TrailNotFoundException":
                raise


def _delete_identity_pool_idempotent(ci, pool_id):
    try:
        ci.delete_identity_pool(IdentityPoolId=pool_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _delete_user_pool_idempotent(idp, pool_id):
    try:
        idp.delete_user_pool(UserPoolId=pool_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _error_code(fn):
    """The exact AWS error code, RAISING if the call unexpectedly SUCCEEDS, so an over-permissive
    target fails as an acceptance, not a code mismatch."""
    try:
        fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message", "")
    raise AssertionError("call unexpectedly SUCCEEDED where an error was required")


def _lookup_all(ct, **kw):
    """Page LookupEvents to exhaustion (bounded)."""
    out = []
    nxt = None
    for _ in range(_PAGE_CEILING):
        if nxt:
            kw["NextToken"] = nxt
        else:
            kw.pop("NextToken", None)
        resp = ct.lookup_events(**kw)
        out.extend(resp["Events"])
        nxt = resp.get("NextToken")
        if not nxt:
            return out
    return out


def _log_prefixes(account, region):
    """The documented key prefixes for management and data events, for today plus a day either
    side -- the delivery date can roll past midnight relative to the call."""
    now = datetime.datetime.now(datetime.timezone.utc)
    days = {now.date(),
            (now + datetime.timedelta(days=1)).date(),
            (now - datetime.timedelta(days=1)).date()}
    base = f"AWSLogs/{account}/CloudTrail/{region}/"
    return [f"{base}{d.year:04d}/{d.month:02d}/{d.day:02d}/" for d in sorted(days)]


class _LogReader:
    """Reads every delivered log file once and accumulates the records. Objects already read are
    never re-fetched, so repeated scans cost only the LIST calls."""

    def __init__(self, s3, bucket, account, region):
        self._s3 = s3
        self._bucket = bucket
        self._account = account
        self._region = region
        self.keys_by_record: list[tuple[str, dict]] = []
        self.seen_keys: set[str] = set()

    def refresh(self) -> int:
        """Fetch and inflate any object not yet read. Returns the number of NEW objects read."""
        paginator = self._s3.get_paginator("list_objects_v2")
        new = 0
        for prefix in _log_prefixes(self._account, self._region):
            for page in paginator.paginate(Bucket=self._bucket, Prefix=prefix):
                for entry in page.get("Contents", []):
                    key = entry["Key"]
                    if key in self.seen_keys:
                        continue
                    self.seen_keys.add(key)
                    new += 1
                    raw = self._s3.get_object(Bucket=self._bucket, Key=key)["Body"].read()
                    assert raw[:2] == b"\x1f\x8b", (
                        f"delivered object {key!r} does not start with the gzip magic bytes "
                        f"1f 8b; first bytes were {raw[:8]!r}. CloudTrail publishes log files "
                        f"in a gzip archive"
                    )
                    payload = json.loads(gzip.decompress(raw).decode("utf-8"))
                    assert isinstance(payload.get("Records"), list), (
                        f"the inflated body of {key!r} has no Records list; top-level keys were "
                        f"{sorted(payload)!r}"
                    )
                    for record in payload["Records"]:
                        self.keys_by_record.append((key, record))
        return new

    def matching(self, *, event_name=None, needle=None):
        out = []
        for key, record in self.keys_by_record:
            if event_name is not None and record.get("eventName") != event_name:
                continue
            if needle is not None and needle not in json.dumps(record):
                continue
            out.append((key, record))
        return out


@tags(
    "axis:negative-delivery",
    "concern:data-plane",
    "concern:eventing",
    "dp:api",
    "plane:data",
    "cap:c2",
)
def run(ctx) -> None:
    """A Cognito identity-pool data event reaches the trail ONLY after an advanced event selector
    names AWS::Cognito::IdentityPool -- and when it does, the caller's token is redacted.
    Data events also never appear in LookupEvents, which records management events only.
    """
    ct = ctx.client("cloudtrail")
    ci = ctx.client("cognito-identity")
    idp = ctx.client("cognito-idp")
    s3 = ctx.client("s3")
    account = ctx.client("sts").get_caller_identity()["Account"]
    region = ctx.region

    # --- A user pool, to be the identity pools' login provider. GetId / GetOpenIdToken need a
    # `logins` map for the redaction leg to have anything to redact (no IAM role needed).
    user_pool = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-ctci-"),
        Policies={"PasswordPolicy": {
            "MinimumLength": 8, "RequireUppercase": True, "RequireLowercase": True,
            "RequireNumbers": True, "RequireSymbols": True,
        }},
        UserPoolTags={"sim2real": CHECK},
    )["UserPool"]
    user_pool_id = user_pool["Id"]
    ctx.on_cleanup(lambda: _delete_user_pool_idempotent(idp, user_pool_id))
    app_client_id = idp.create_user_pool_client(
        UserPoolId=user_pool_id,
        ClientName=ctx.unique_name("sim2real-behav-ctci-c-"),
        GenerateSecret=False,
        ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )["UserPoolClient"]["ClientId"]
    provider_name = f"cognito-idp.{region}.amazonaws.com/{user_pool_id}"

    user_name = ctx.unique_name("sim2realctciuser")
    password_token = ctx.unique_name("Ctci").replace("-", "")
    idp.admin_create_user(
        UserPoolId=user_pool_id, Username=user_name, MessageAction="SUPPRESS"
    )
    idp.admin_set_user_password(
        UserPoolId=user_pool_id, Username=user_name,
        Password=f"Aa1!{password_token}", Permanent=True,
    )
    auth = idp.initiate_auth(
        AuthFlow="USER_PASSWORD_AUTH",
        ClientId=app_client_id,
        AuthParameters={"USERNAME": user_name, "PASSWORD": f"Aa1!{password_token}"},
    )
    assert "AuthenticationResult" in auth, (
        f"InitiateAuth did not authenticate the user this check just created; response keys were "
        f"{sorted(auth)!r}. Without an ID token there is no `logins` map and nothing to redact"
    )
    id_token = auth["AuthenticationResult"]["IdToken"]
    assert id_token, "InitiateAuth returned an empty IdToken"

    # --- Two identity pools, configured IDENTICALLY. The selector is scoped by resources.type,
    # so the only thing that will differ between them is whether it existed at call time.
    def _make_pool(label):
        pool = _call(lambda: ci.create_identity_pool(
            IdentityPoolName=ctx.unique_name(f"sim2real_behav_ctci_{label}_"),
            AllowUnauthenticatedIdentities=False,
            CognitoIdentityProviders=[{
                "ProviderName": provider_name,
                "ClientId": app_client_id,
                # Deliberately False and NOT the subject of this check -- see the docstring.
                "ServerSideTokenCheck": False,
            }],
            IdentityPoolTags={"sim2real": CHECK},
        ))
        pool_id = pool["IdentityPoolId"]
        ctx.on_cleanup(lambda: _delete_identity_pool_idempotent(ci, pool_id))
        return pool_id, f"arn:aws:cognito-identity:{region}:{account}:identitypool/{pool_id}"

    pool_a_id, pool_a_arn = _make_pool("a")
    pool_b_id, pool_b_arn = _make_pool("b")
    assert pool_a_id != pool_b_id, (
        f"both identity pools came back as {pool_a_id!r}; the withheld/delivered comparison needs "
        f"two distinct pools"
    )

    # --- The trail, with DEFAULT selectors: management events only, no data events.
    bucket = ctx.unique_name("sim2real-behav-ctci-")
    trail_name = ctx.unique_name("sim2real-behav-ctci-")
    _create_trail_bucket(s3, bucket, region, account)
    ctx.on_cleanup(lambda: _drain_and_delete_bucket(s3, bucket))
    _call(lambda: ct.create_trail(
        Name=trail_name,
        S3BucketName=bucket,
        IsMultiRegionTrail=False,
        IncludeGlobalServiceEvents=False,
        TagsList=[{"Key": "sim2real", "Value": CHECK}],
    ))
    ctx.on_cleanup(lambda: _delete_trail_idempotent(ct, trail_name))
    baseline = _call(lambda: ct.get_event_selectors(TrailName=trail_name))
    assert baseline["EventSelectors"][0]["DataResources"] == [], (
        f"a new trail reports DataResources "
        f"{baseline['EventSelectors'][0]['DataResources']!r}; the documented default is "
        f"management events only. The withheld half below is meaningless if data events are "
        f"selected by default"
    )
    assert "AdvancedEventSelectors" not in baseline, (
        f"a new trail already reports AdvancedEventSelectors "
        f"{baseline.get('AdvancedEventSelectors')!r}; expected the member to be absent until one "
        f"is put"
    )
    _call(lambda: ct.start_logging(Name=trail_name))
    status = _call(lambda: ct.get_trail_status(Name=trail_name))
    assert status["IsLogging"] is True, (
        f"GetTrailStatus reports IsLogging={status.get('IsLogging')!r} right after StartLogging; "
        f"expected True. Every leg below assumes the trail was live throughout"
    )

    # --- WARM-UP: management-event rounds until one is delivered, so the trail is demonstrably
    # capturing before the withheld calls are made.
    reader = _LogReader(s3, bucket, account, region)
    warm_tokens = []
    warm_t0 = time.monotonic()
    next_round_at = warm_t0
    while True:
        if time.monotonic() >= next_round_at:
            warm_token = ctx.unique_name("sim2realctciwarm").lower()
            _call(lambda: ci.tag_resource(
                ResourceArn=pool_b_arn, Tags={"sim2real-warm": warm_token}
            ))
            warm_tokens.append(warm_token)
            next_round_at = time.monotonic() + _ROUND_INTERVAL_S
        time.sleep(_DELIVERY_POLL_S)
        reader.refresh()
        if any(reader.matching(event_name="TagResource", needle=t) for t in warm_tokens):
            break
        assert time.monotonic() - warm_t0 < _WARM_BUDGET_S, (
            f"{DATAPLANE_MARKER}: none of {len(warm_tokens)} cognito-identity:TagResource "
            f"management calls was delivered to {bucket!r} within {_WARM_BUDGET_S:.0f}s; "
            f"{len(reader.seen_keys)} object(s) read. GetTrailStatus: "
            f"{_call(lambda: ct.get_trail_status(Name=trail_name))!r}"
        )

    # --- WITHHELD: data-plane calls against pool A while no data selector exists.
    withheld_at = datetime.datetime.now(datetime.timezone.utc)
    identity_a = _call(lambda: ci.get_id(
        IdentityPoolId=pool_a_id, Logins={provider_name: id_token}
    ))["IdentityId"]
    _call(lambda: ci.get_open_id_token(
        IdentityId=identity_a, Logins={provider_name: id_token}
    ))

    # --- Repair exactly one thing: the selector AWS publishes for this service.
    advanced = [{
        "Name": "sim2real-behav-cognito-identity-pools",
        "FieldSelectors": [
            {"Field": "eventCategory", "Equals": ["Data"]},
            {"Field": "resources.type", "Equals": [_POOL_RESOURCE_TYPE]},
        ],
    }, {
        # Advanced selectors replace the default management selector; the marker needs it.
        "Name": "sim2real-behav-management",
        "FieldSelectors": [{"Field": "eventCategory", "Equals": ["Management"]}],
    }]
    put = _call(
        lambda: ct.put_event_selectors(TrailName=trail_name, AdvancedEventSelectors=advanced)
    )
    assert put["AdvancedEventSelectors"] == advanced, (
        f"PutEventSelectors echoed {put.get('AdvancedEventSelectors')!r}, expected the selector "
        f"submitted ({advanced!r})"
    )
    stored = _call(lambda: ct.get_event_selectors(TrailName=trail_name))
    assert stored["AdvancedEventSelectors"] == advanced, (
        f"GetEventSelectors returns {stored.get('AdvancedEventSelectors')!r}, expected "
        f"{advanced!r}. The resource type is {_POOL_RESOURCE_TYPE!r} -- a target that normalises "
        f"it, reorders the field selectors, or drops the eventCategory clause fails here"
    )
    assert "EventSelectors" not in stored, (
        f"the trail still reports basic EventSelectors {stored.get('EventSelectors')!r} after "
        f"AdvancedEventSelectors were applied; applying advanced selectors overwrites any "
        f"existing basic ones"
    )
    selector_at = datetime.datetime.now(datetime.timezone.utc)

    # --- DELIVERED: the same two operations against pool B, now that the selector names the type,
    # then the management marker LAST: barrier and latency measurement in one. Repeated each round
    # until a round's marker and pool B's data events have both landed.
    rounds = []
    marker_record = None
    polls = 0
    t_start = time.monotonic()
    next_round_at = t_start
    while True:
        if time.monotonic() >= next_round_at:
            identity_b = _call(lambda: ci.get_id(
                IdentityPoolId=pool_b_id, Logins={provider_name: id_token}
            ))["IdentityId"]
            _call(lambda: ci.get_open_id_token(
                IdentityId=identity_b, Logins={provider_name: id_token}
            ))
            round_token = ctx.unique_name("sim2realctcimarker").lower()
            rounds.append(
                (round_token, datetime.datetime.now(datetime.timezone.utc), time.monotonic())
            )
            _call(lambda: ci.tag_resource(
                ResourceArn=pool_a_arn, Tags={"sim2real-marker": round_token}
            ))
            next_round_at = time.monotonic() + _ROUND_INTERVAL_S
        time.sleep(_DELIVERY_POLL_S)
        polls += 1
        reader.refresh()
        data_landed = all(
            reader.matching(event_name=n, needle=pool_b_arn)
            or reader.matching(event_name=n, needle=pool_b_id)
            for n in _DATA_EVENT_NAMES
        )
        for token, at, t_mono in rounds:
            hits = reader.matching(event_name="TagResource", needle=token)
            if hits and data_landed:
                marker_record, marker_token, marker_at, t0 = hits[0][1], token, at, t_mono
                break
        if marker_record is not None or time.monotonic() - t_start >= _DELIVERY_BUDGET_S:
            break
    if marker_record is None:
        marker_token, marker_at, t0 = rounds[-1]
    latency_s = time.monotonic() - t0

    if marker_record is None:
        diag_status = _call(lambda: ct.get_trail_status(Name=trail_name))
    assert marker_record is not None, (
        f"{DATAPLANE_MARKER}: the trail delivered no log file containing the MANAGEMENT event "
        f"this check made last. Trail {trail_name!r} was logging to {bucket!r}; a "
        f"cognito-identity:TagResource carrying the token {marker_token!r} was made at "
        f"{marker_at.isoformat()}; {polls} polls over {latency_s:.0f}s read "
        f"{len(reader.seen_keys)} object(s) under AWSLogs/{account}/CloudTrail/{region}/ and none "
        f"mentioned it. GetTrailStatus reports IsLogging={diag_status.get('IsLogging')!r}, "
        f"LatestDeliveryTime={diag_status.get('LatestDeliveryTime')!r}, "
        f"LatestDeliveryError={diag_status.get('LatestDeliveryError')!r}, "
        f"LatestNotificationError={diag_status.get('LatestNotificationError')!r}. Real AWS "
        f"documents delivery at an average of about 5 minutes. Nothing below is interpretable "
        f"without this: it is both the positive control for the pipeline and the barrier the "
        f"absence assertion rests on"
    )
    assert marker_record["eventCategory"] == "Management", (
        f"cognito-identity:TagResource is audited with eventCategory "
        f"{marker_record.get('eventCategory')!r}, expected Management. AWS documents 'the "
        f"remainder of Amazon Cognito identity pools API operations' as management events, and if "
        f"the target classifies tagging as Data the whole partition under test is inverted"
    )
    assert marker_record["managementEvent"] is True, (
        f"the TagResource record reports managementEvent "
        f"{marker_record.get('managementEvent')!r}, expected True"
    )

    # --- Hold a further 1xL, re-reading every new object, before declaring the absence. L is the
    # delivery latency MEASURED on this exact wiring seconds ago, not a guess -- and the withheld
    # calls happened BEFORE the marker, so a correct pipeline would already have shipped them.
    absence_hold_s = min(max(latency_s * _ABSENCE_MULTIPLE, 60.0), _ABSENCE_CEILING_S)
    hold_start = time.monotonic()
    while time.monotonic() - hold_start < absence_hold_s:
        reader.refresh()
        time.sleep(_DELIVERY_POLL_S)
    reader.refresh()

    # --- The DELIVERED half: pool B's data events are there, and audited as data events.
    for event_name in _DATA_EVENT_NAMES:
        hits = reader.matching(event_name=event_name, needle=pool_b_arn)
        if not hits:
            hits = reader.matching(event_name=event_name, needle=pool_b_id)
        assert hits, (
            f"{DATAPLANE_MARKER}: cognito-identity:{event_name} was called against pool "
            f"{pool_b_id!r} at {selector_at.isoformat()}, AFTER an advanced event selector naming "
            f"eventCategory=Data and resources.type={_POOL_RESOURCE_TYPE} was accepted and read "
            f"back -- and no such record was delivered. {len(reader.seen_keys)} object(s) were "
            f"read over {latency_s:.0f}s plus a {absence_hold_s:.0f}s hold, and the management "
            f"marker WAS delivered in the same window, so the pipeline works. A target whose data "
            f"selector round-trips but selects nothing fails here"
        )
        key, record = hits[0]
        assert record["eventSource"] == "cognito-identity.amazonaws.com", (
            f"{event_name}: eventSource is {record.get('eventSource')!r}, expected "
            f"cognito-identity.amazonaws.com"
        )
        assert record["eventCategory"] == "Data", (
            f"{event_name} (delivered at {key!r}) is audited with eventCategory "
            f"{record.get('eventCategory')!r}, expected 'Data'. AWS enumerates GetId, "
            f"GetOpenIdToken, GetCredentialsForIdentity, GetOpenIdTokenForDeveloperIdentity and "
            f"UnlinkIdentity as data events; every data-event cost control and Athena query keys "
            f"on this field"
        )
        assert record["managementEvent"] is False, (
            f"{event_name}: managementEvent is {record.get('managementEvent')!r}, expected False. "
            f"The two members must agree -- a target that sets eventCategory correctly and leaves "
            f"managementEvent true is internally inconsistent"
        )
        resources = record["resources"]
        types = [r.get("type") for r in resources]
        assert _POOL_RESOURCE_TYPE in types, (
            f"{event_name}: the record's resources report types {types!r}; expected one of type "
            f"{_POOL_RESOURCE_TYPE!r}. That value is exactly what the selector matched on, so if "
            f"the record does not carry it the selector cannot have selected the event"
        )
        arns = [r.get("ARN") for r in resources if r.get("type") == _POOL_RESOURCE_TYPE]
        assert pool_b_arn in arns, (
            f"{event_name}: the record's {_POOL_RESOURCE_TYPE} resources name {arns!r}, expected "
            f"the pool the call addressed ({pool_b_arn!r})"
        )
        accounts = [r.get("accountId") for r in resources if r.get("type") == _POOL_RESOURCE_TYPE]
        assert accounts == [account] * len(accounts), (
            f"{event_name}: the resources entries report accountId {accounts!r}, expected "
            f"{account!r} for every one"
        )

        # --- the token map is redacted, and the token itself is nowhere in the bytes.
        parameters = record["requestParameters"]
        assert parameters is not None, (
            f"{event_name}: requestParameters is null on a SUCCESSFUL call; real AWS records the "
            f"arguments with the private fields OBSCURED, not the object dropped -- and dropping "
            f"it loses identityPoolId and identityId, which every audit query needs"
        )
        assert "logins" in parameters, (
            f"{event_name}: requestParameters has no `logins` member: {sorted(parameters)!r}. The "
            f"call supplied one, and real AWS keeps the member while replacing its VALUES, so a "
            f"consumer can still see that a federated token was presented"
        )
        logins = parameters["logins"]
        assert isinstance(logins, dict), (
            f"{event_name}: requestParameters.logins is a {type(logins).__name__} "
            f"({logins!r}); the documented shape is a MAP whose KEYS are provider names and whose "
            f"VALUES are replaced -- unlike cognito-idp's authParameters, where the whole map "
            f"becomes a string. The two services obscure at different depths"
        )
        assert logins.get(provider_name) == _REDACTED, (
            f"{event_name}: requestParameters.logins[{provider_name!r}] is "
            f"{logins.get(provider_name)!r}, expected the exact literal {_REDACTED!r}. Keys "
            f"present: {sorted(logins)!r}"
        )
        assert id_token not in json.dumps(record), (
            f"{event_name}: the live Cognito ID token this check presented (length "
            f"{len(id_token)}, prefix {id_token[:12]!r}) appears in the delivered log file "
            f"{key!r}. A credential is now in an audit log, and a customer's CloudTrail retention "
            f"and access posture assumes that cannot happen"
        )

    # --- The WITHHELD half. Two independent observables, and the barrier above.
    withheld = []
    for event_name in _DATA_EVENT_NAMES:
        withheld.extend(reader.matching(event_name=event_name, needle=pool_a_arn))
        withheld.extend(reader.matching(event_name=event_name, needle=pool_a_id))
        withheld.extend(reader.matching(event_name=event_name, needle=identity_a))
    assert withheld == [], (
        f"{len(withheld)} data-event record(s) for pool A ({pool_a_id!r}) were delivered: "
        f"{[(k, r.get('eventName')) for k, r in withheld[:5]]!r}. Those calls were made at "
        f"{withheld_at.isoformat()}, BEFORE the data selector was applied at "
        f"{selector_at.isoformat()}, and AWS documents that data events are not logged by default "
        f"and require the selector. Pool A and pool B are configured identically and the selector "
        f"is scoped by resources.type, so the ONLY difference is whether it was in effect. A "
        f"target that logs identity-pool calls unconditionally lands here -- and it would silently "
        f"bill a customer for data events they never enabled. Delivery is demonstrably working: "
        f"pool B's records and the management marker both arrived, measured latency "
        f"{latency_s:.0f}s, held a further {absence_hold_s:.0f}s across "
        f"{len(reader.seen_keys)} object(s)"
    )
    final_status = _call(lambda: ct.get_trail_status(Name=trail_name))
    assert "LatestDeliveryTime" in final_status, (
        f"GetTrailStatus omits LatestDeliveryTime on a trail that demonstrably delivered "
        f"{len(reader.seen_keys)} object(s); response keys were {sorted(final_status)!r}"
    )
    marker_event_time = marker_record["eventTime"]
    assert final_status["LatestDeliveryTime"] >= marker_at - datetime.timedelta(minutes=1), (
        f"LatestDeliveryTime {final_status['LatestDeliveryTime']!r} predates the management "
        f"marker's own instant ({marker_at.isoformat()}, recorded eventTime "
        f"{marker_event_time!r}), so the trail's own status does not agree that it has delivered "
        f"past the point the withheld calls occupy. This is the second observable the absence "
        f"rests on"
    )
    assert "LatestDeliveryError" not in final_status, (
        f"GetTrailStatus reports LatestDeliveryError "
        f"{final_status.get('LatestDeliveryError')!r} on a trail that delivered "
        f"{len(reader.seen_keys)} object(s); a delivery failure would explain the absence above "
        f"for the wrong reason"
    )

    # --- data events are not in event history, however long they have been indexed -- and
    # the management marker in the same window is the control that makes the absence meaningful.
    history = _lookup_all(
        ct,
        StartTime=withheld_at - datetime.timedelta(minutes=2),
        EndTime=datetime.datetime.now(datetime.timezone.utc),
        MaxResults=50,
    )
    assert history, (
        "an unfiltered LookupEvents over the window returned no events at all, so the absence "
        "assertion below would pass vacuously"
    )
    marker_in_history = [
        ev for ev in history if marker_token in ev.get("CloudTrailEvent", "")
    ]
    assert marker_in_history, (
        f"{DATAPLANE_MARKER}: the MANAGEMENT marker {marker_token!r} is not in event history "
        f"either, after {latency_s + absence_hold_s:.0f}s -- and it is the control for the data "
        f"events' absence. {len(history)} events were returned for the window"
    )
    data_in_history = [
        (ev.get("EventId"), ev.get("EventName"))
        for ev in history
        if ev.get("EventName") in _DATA_EVENT_NAMES
        and (pool_a_id in ev.get("CloudTrailEvent", "")
             or pool_b_id in ev.get("CloudTrailEvent", ""))
    ]
    assert data_in_history == [], (
        f"{len(data_in_history)} identity-pool DATA event(s) appear in event history: "
        f"{data_in_history[:5]!r}. Event history shows the past 90 days of MANAGEMENT events "
        f"only; data events require a trail or an event data store. Pool B's data events were "
        f"demonstrably captured (they are in the delivered log files) and the management marker "
        f"is demonstrably in event history, so this absence is the partition and not a gap in the "
        f"pipeline"
    )

    # --- Teardown is proved, with operations that demonstrably worked earlier.
    _call(lambda: ct.stop_logging(Name=trail_name))
    _call(lambda: ct.delete_trail(Name=trail_name))
    code, message = _error_code(lambda: ct.get_event_selectors(TrailName=trail_name))
    assert code == "TrailNotFoundException", (
        f"GetEventSelectors on the deleted trail {trail_name!r} -- which returned the "
        f"{_POOL_RESOURCE_TYPE} selector minutes ago -- answered {code!r}, expected "
        f"TrailNotFoundException"
    )
    trail_arn = f"arn:aws:cloudtrail:{region}:{account}:trail/{trail_name}"
    assert message == f"Unknown trail: {trail_arn} for the user: {account}", (
        f"GetEventSelectors on the deleted trail answered {message!r}"
    )
    _call(lambda: ci.delete_identity_pool(IdentityPoolId=pool_b_id))
    code, message = _error_code(lambda: ci.get_id(
        IdentityPoolId=pool_b_id, Logins={provider_name: id_token}
    ))
    assert code == "ResourceNotFoundException", (
        f"GetId on the deleted identity pool {pool_b_id!r} -- which succeeded earlier in this "
        f"run -- answered {code!r}, expected ResourceNotFoundException; a deleted pool must be "
        f"unusable, not merely unreadable"
    )
    assert message == f"IdentityPool '{pool_b_id}' not found.", (
        f"GetId on the deleted identity pool answered {message!r}"
    )

    # Drain the log bucket here, inside the body's budget: the trail is already stopped and
    # deleted, so only objects already in flight can still land. The on_cleanup registration
    # above is the backstop for an early exit.
    _drain_and_delete_bucket(s3, bucket)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
