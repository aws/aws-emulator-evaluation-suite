"""obs-cognito-identity-2-identity-pool-data-events-are-delivered-redacted-and-never-in-event-history."""

from __future__ import annotations

import datetime
import gzip
import json
import sys
import time

from botocore import UNSIGNED
from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "obs-cognito-identity-2-identity-pool-data-events-are-delivered-redacted-and-never-in-event-history"
GROUP = "eventing"
SERVICES = ["cloudtrail", "cognito-identity"]

# Marks a missing delivery as a data-plane fidelity failure, not a connection error.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

_REDACTED = "HIDDEN_DUE_TO_SECURITY_REASONS"
_POOL_RESOURCE_TYPE = "AWS::Cognito::IdentityPool"
_UNSIGNED_OPS = ("GetId", "GetOpenIdToken", "GetCredentialsForIdentity", "UnlinkIdentity")
_SIGNED_OP = "GetOpenIdTokenForDeveloperIdentity"
_ALL_OPS = _UNSIGNED_OPS + (_SIGNED_OP,)

# Delivery: a new data selector's activation lag (between 10 s and 11 min) plus CloudTrail's
# ~5 min average S3 delivery.
_DELIVERY_TIMEOUT_S = 1260.0
_ROUND_INTERVAL_S = 60.0
_POLL_S = 2.0
# Event-history indexing for the CreateIdentityPool control. By the time an S3 file has landed
# (>= 5 min after the create) it is normally already indexed, so this rarely waits at all.
_INDEX_CEILING_S = 240.0
# IAM propagation for the two roles this check creates (first use of each, bounded).
_IAM_PROPAGATION_CEILING_S = 90.0
_PAGE_CEILING = 40


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


def _until(fn, retry_codes, ceiling_s):
    """Invoke fn() until it stops raising one of retry_codes (IAM/role propagation), bounded."""
    deadline = time.monotonic() + ceiling_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in retry_codes or time.monotonic() > deadline:
                raise
            time.sleep(5.0)


def _create_trail_bucket(s3, bucket, region, account_id):
    kwargs = {"Bucket": bucket}
    # CreateBucket rejects an explicit us-east-1 LocationConstraint; the literal selects the
    # request shape, the bucket lives in ctx.region either way.
    if region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": region}
    s3.create_bucket(**kwargs)


def _put_trail_bucket_policy(s3, bucket, account_id):
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK[:200]}]}
    )
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
                "Condition": {
                    "StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}
                },
            },
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))


def _purge_bucket_once(s3, bucket):
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
        except ClientError:
            continue


def _drain_and_delete_bucket(s3, bucket, *, attempts=8, delay_s=15.0):
    """Empty and delete the log bucket, retrying because CloudTrail may still be writing.

    Raises on a deadline miss so a leaked bucket is visible."""
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


def _ignore_not_found(fn, codes=("ResourceNotFoundException", "NoSuchEntity")):
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in codes:
            raise


def _delete_role(iam, role_name):
    try:
        for name in iam.list_role_policies(RoleName=role_name)["PolicyNames"]:
            iam.delete_role_policy(RoleName=role_name, PolicyName=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise
    _ignore_not_found(lambda: iam.delete_role(RoleName=role_name))


def _lookup_all(ct, **kw):
    """Page LookupEvents to exhaustion (bounded), pacing for its 2 TPS account limit."""
    out = []
    nxt = None
    for _ in range(_PAGE_CEILING):
        if nxt:
            kw["NextToken"] = nxt
        else:
            kw.pop("NextToken", None)
        resp = _call(lambda: ct.lookup_events(**kw))
        out.extend(resp["Events"])
        nxt = resp.get("NextToken")
        if not nxt:
            return out
        time.sleep(0.6)
    return out


def _show(record):
    """A record, compact and bounded, for an assertion message."""
    return json.dumps(record, sort_keys=True, default=str)[:1800]


class _LogReader:
    """Reads every delivered log file under the account's CloudTrail prefix once."""

    def __init__(self, s3, bucket, account, region):
        self._s3 = s3
        self._bucket = bucket
        self._prefix = f"AWSLogs/{account}/CloudTrail/{region}/"
        self.seen_keys: set[str] = set()
        self.by_request_id: dict[str, list[tuple[str, dict]]] = {}

    def refresh(self) -> None:
        paginator = self._s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=self._bucket, Prefix=self._prefix):
            for entry in page.get("Contents", []):
                key = entry["Key"]
                if key in self.seen_keys or not key.endswith(".json.gz"):
                    continue
                self.seen_keys.add(key)
                raw = self._s3.get_object(Bucket=self._bucket, Key=key)["Body"].read()
                assert raw[:2] == b"\x1f\x8b", (
                    f"delivered object {key!r} does not start with the gzip magic bytes; first "
                    f"bytes were {raw[:8]!r}"
                )
                payload = json.loads(gzip.decompress(raw).decode("utf-8"))
                assert isinstance(payload.get("Records"), list), (
                    f"the inflated body of {key!r} has no Records list; keys {sorted(payload)!r}"
                )
                for record in payload["Records"]:
                    rid = record.get("requestID")
                    if rid:
                        self.by_request_id.setdefault(rid, []).append((key, record))


@tags(
    "axis:negative-delivery",
    "concern:data-plane",
    "concern:eventing",
    "dp:api",
    "plane:data",
    "cap:c2",
    "cap:c7",
)
def run(ctx) -> None:
    """The five Cognito identity-pool data operations reach a trail as redacted data events against
    the pool, joined to each call by requestID, yet none appear in LookupEvents while the pool's
    CreateIdentityPool management event does.

    Reference: https://docs.aws.amazon.com/cognito/latest/developerguide/logging-using-cloudtrail.html
    """
    ct = ctx.client("cloudtrail")
    ci = ctx.client("cognito-identity")
    ci_unsigned = ctx.client("cognito-identity", config=Config(signature_version=UNSIGNED))
    idp = ctx.client("cognito-idp")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]
    region = ctx.region
    window_start = datetime.datetime.now(datetime.timezone.utc)
    tag = ctx.unique_name("")  # 12 hex, shared by every name this run creates

    # Trail first, so the selector's activation lag overlaps the rest of setup. Bucket teardown is
    # registered first so it runs last, after the trail.
    bucket = f"sim2real-xsvc-ctci2-{tag}"
    trail_name = f"sim2real-xsvc-ctci2-{tag}"
    _create_trail_bucket(s3, bucket, region, account)
    ctx.on_cleanup(lambda: _drain_and_delete_bucket(s3, bucket))
    _put_trail_bucket_policy(s3, bucket, account)
    _call(lambda: ct.create_trail(
        Name=trail_name,
        S3BucketName=bucket,
        IsMultiRegionTrail=False,
        IncludeGlobalServiceEvents=False,
        TagsList=[{"Key": "sim2real", "Value": CHECK[:256]}],
    ))
    ctx.on_cleanup(lambda: _delete_trail_idempotent(ct, trail_name))
    selector = [{
        "Name": "sim2real-cognito-identity-pool-data",
        "FieldSelectors": [
            {"Field": "eventCategory", "Equals": ["Data"]},
            {"Field": "resources.type", "Equals": [_POOL_RESOURCE_TYPE]},
        ],
    }]
    put = _call(lambda: ct.put_event_selectors(
        TrailName=trail_name, AdvancedEventSelectors=selector
    ))
    assert put["AdvancedEventSelectors"] == selector, (
        f"PutEventSelectors echoed {put.get('AdvancedEventSelectors')!r}, expected {selector!r}"
    )
    _call(lambda: ct.start_logging(Name=trail_name))
    status = _call(lambda: ct.get_trail_status(Name=trail_name))
    assert status["IsLogging"] is True, (
        f"GetTrailStatus reports IsLogging={status.get('IsLogging')!r} right after StartLogging"
    )

    # A user pool: the federated provider whose ID token fills the `logins` map.
    user_pool_id = idp.create_user_pool(
        PoolName=f"sim2real-xsvc-ctci2-{tag}", UserPoolTags={"sim2real": CHECK[:256]},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: idp.delete_user_pool(UserPoolId=user_pool_id)))
    app_client_id = idp.create_user_pool_client(
        UserPoolId=user_pool_id,
        ClientName=f"sim2real-xsvc-ctci2-{tag}",
        GenerateSecret=False,
        ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )["UserPoolClient"]["ClientId"]
    provider_name = f"cognito-idp.{region}.amazonaws.com/{user_pool_id}"
    developer_provider = f"sim2real.ctci2.{tag}"

    pool_id = _call(lambda: ci.create_identity_pool(
        IdentityPoolName=f"sim2real_xsvc_ctci2_{tag}",
        AllowUnauthenticatedIdentities=False,
        DeveloperProviderName=developer_provider,
        CognitoIdentityProviders=[{
            "ProviderName": provider_name,
            "ClientId": app_client_id,
            "ServerSideTokenCheck": False,
        }],
        IdentityPoolTags={"sim2real": CHECK[:256]},
    ))["IdentityPoolId"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id)))
    pool_arn = f"arn:aws:cognito-identity:{region}:{account}:identitypool/{pool_id}"

    # The authenticated role GetCredentialsForIdentity vends (no permissions attached).
    auth_role_name = f"sim2real-xsvc-ctci2-auth-{tag}"
    auth_role_arn = iam.create_role(
        RoleName=auth_role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Federated": "cognito-identity.amazonaws.com"},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringEquals": {"cognito-identity.amazonaws.com:aud": pool_id},
                    "ForAnyValue:StringLike": {"cognito-identity.amazonaws.com:amr": "authenticated"},
                },
            }],
        }),
        Tags=[{"Key": "sim2real", "Value": "obs-cognito-identity-2"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, auth_role_name))
    _call(lambda: ci.set_identity_pool_roles(
        IdentityPoolId=pool_id, Roles={"authenticated": auth_role_arn}
    ))

    # The signed caller is deliberately an assumed role, so the record's userIdentity is
    # AssumedRole + sessionContext whatever principal runs the check.
    dev_role_name = f"sim2real-xsvc-ctci2-dev-{tag}"
    dev_role_arn = iam.create_role(
        RoleName=dev_role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                "Action": "sts:AssumeRole",
            }],
        }),
        Tags=[{"Key": "sim2real", "Value": "obs-cognito-identity-2"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, dev_role_name))
    iam.put_role_policy(
        RoleName=dev_role_name,
        PolicyName="developer-identity",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "cognito-identity:GetOpenIdTokenForDeveloperIdentity",
                "Resource": pool_arn,
            }],
        }),
    )
    session_name = f"sim2real-ctci2-{tag}"
    assumed = _until(
        lambda: sts.assume_role(RoleArn=dev_role_arn, RoleSessionName=session_name),
        ("AccessDenied",), _IAM_PROPAGATION_CEILING_S,
    )["Credentials"]
    ci_dev = ctx.client("cognito-identity", creds={
        "aws_access_key_id": assumed["AccessKeyId"],
        "aws_secret_access_key": assumed["SecretAccessKey"],
        "aws_session_token": assumed["SessionToken"],
    })

    def _round(n):
        """One call of each of the five operations. Returns {op: (request_id, context)}."""
        user = f"sim2realctci2u{n}{tag}"
        password = f"Aa1!{ctx.unique_name('')}"
        idp.admin_create_user(UserPoolId=user_pool_id, Username=user, MessageAction="SUPPRESS")
        idp.admin_set_user_password(
            UserPoolId=user_pool_id, Username=user, Password=password, Permanent=True
        )
        id_token = idp.initiate_auth(
            AuthFlow="USER_PASSWORD_AUTH", ClientId=app_client_id,
            AuthParameters={"USERNAME": user, "PASSWORD": password},
        )["AuthenticationResult"]["IdToken"]
        logins = {provider_name: id_token}
        out = {}
        r = _call(lambda: ci_unsigned.get_id(IdentityPoolId=pool_id, Logins=logins))
        identity_id = r["IdentityId"]
        out["GetId"] = (r["ResponseMetadata"]["RequestId"], {})
        r = _call(lambda: ci_unsigned.get_open_id_token(IdentityId=identity_id, Logins=logins))
        assert r["Token"], f"GetOpenIdToken returned no Token: {sorted(r)!r}"
        out["GetOpenIdToken"] = (r["ResponseMetadata"]["RequestId"], {"token": r["Token"]})
        r = _until(
            lambda: ci_unsigned.get_credentials_for_identity(IdentityId=identity_id, Logins=logins),
            ("InvalidIdentityPoolConfigurationException",), _IAM_PROPAGATION_CEILING_S,
        )
        out["GetCredentialsForIdentity"] = (
            r["ResponseMetadata"]["RequestId"], {"secret": r["Credentials"]["SecretKey"]}
        )
        r = _until(
            lambda: ci_dev.get_open_id_token_for_developer_identity(
                IdentityPoolId=pool_id, Logins={developer_provider: f"devuser-{n}-{tag}"}
            ),
            ("AccessDeniedException", "NotAuthorizedException"), _IAM_PROPAGATION_CEILING_S,
        )
        out[_SIGNED_OP] = (
            r["ResponseMetadata"]["RequestId"],
            {"token": r["Token"], "developer_user": f"devuser-{n}-{tag}"},
        )
        r = _call(lambda: ci_unsigned.unlink_identity(
            IdentityId=identity_id, Logins=logins, LoginsToRemove=[provider_name]
        ))
        out["UnlinkIdentity"] = (r["ResponseMetadata"]["RequestId"], {})
        for op in out:
            out[op][1].update(identity_id=identity_id, id_token=id_token)
        return out

    # Calls made right after the selector is applied may never be delivered (activation lag), so
    # issue a fresh round every _ROUND_INTERVAL_S until one lands, then grade a complete round.
    reader = _LogReader(s3, bucket, account, region)
    rounds = []
    t0 = time.monotonic()
    next_round_at = t0
    complete = None
    while time.monotonic() - t0 < _DELIVERY_TIMEOUT_S:
        if not reader.by_request_id and time.monotonic() >= next_round_at:
            rounds.append(_round(len(rounds)))
            next_round_at = time.monotonic() + _ROUND_INTERVAL_S
        reader.refresh()
        for rnd in rounds:
            if all(rid in reader.by_request_id for rid, _ in rnd.values()):
                complete = rnd
                break
        if complete is not None:
            break
        time.sleep(_POLL_S)
    waited = time.monotonic() - t0
    delivered_ops = sorted({
        op for rnd in rounds for op, (rid, _) in rnd.items() if rid in reader.by_request_id
    })
    assert complete is not None, (
        f"{DATAPLANE_MARKER}: no round of the five identity-pool data operations was delivered "
        f"in full. {len(rounds)} round(s) were issued over {waited:.0f}s against pool {pool_id!r} "
        f"after an advanced event selector naming eventCategory=Data and "
        f"resources.type={_POOL_RESOURCE_TYPE} was accepted on trail {trail_name!r}; "
        f"{len(reader.seen_keys)} log file(s) were read and the operations delivered from any "
        f"round were {delivered_ops!r}. Last GetTrailStatus: "
        f"{json.dumps(_call(lambda: ct.get_trail_status(Name=trail_name)), default=str)[:600]}"
    )
    print(f"[obs-cognito-identity-2] round {rounds.index(complete)} of {len(rounds)} delivered "
          f"in full after {waited:.0f}s; {len(reader.seen_keys)} log file(s)", file=sys.stderr)

    identity_ids = {ctx_["identity_id"] for rnd in rounds for _, ctx_ in rnd.values()}
    for op in _ALL_OPS:
        rid, call = complete[op]
        hits = reader.by_request_id[rid]
        assert len(hits) == 1, (
            f"{op}: requestID {rid!r} appears in {len(hits)} delivered records; one call is one "
            f"record. Keys: {[k for k, _ in hits]!r}"
        )
        key, record = hits[0]
        shown = _show(record)
        assert record["eventName"] == op, (
            f"requestID {rid!r} (the {op} call) is delivered as eventName "
            f"{record.get('eventName')!r}: {shown}"
        )
        assert record["eventSource"] == "cognito-identity.amazonaws.com", (
            f"{op}: eventSource {record.get('eventSource')!r}: {shown}"
        )

        if op in _UNSIGNED_OPS:
            assert record["userIdentity"] == {"type": "Unknown"}, (
                f"{op} was sent UNSIGNED, so CloudTrail has no principal to attribute it to; "
                f"userIdentity must be exactly {{'type': 'Unknown'}}, got "
                f"{record.get('userIdentity')!r}"
            )
        else:
            uid = record["userIdentity"]
            assert uid.get("type") == "AssumedRole", (
                f"{op} was signed with credentials from sts:AssumeRole on {dev_role_arn!r}; "
                f"userIdentity.type is {uid.get('type')!r}, expected 'AssumedRole': {uid!r}"
            )
            assert uid.get("arn") == f"arn:aws:sts::{account}:assumed-role/{dev_role_name}/{session_name}", (
                f"{op}: userIdentity.arn is {uid.get('arn')!r}, expected the assumed-role session "
                f"arn:aws:sts::{account}:assumed-role/{dev_role_name}/{session_name}"
            )
            assert uid.get("accountId") == account, (
                f"{op}: userIdentity.accountId {uid.get('accountId')!r}, expected {account!r}"
            )
            session = uid.get("sessionContext")
            assert isinstance(session, dict), (
                f"{op}: an AssumedRole userIdentity carries a sessionContext; got {uid!r}"
            )
            issuer = session.get("sessionIssuer", {})
            assert issuer.get("type") == "Role" and issuer.get("arn") == dev_role_arn, (
                f"{op}: sessionContext.sessionIssuer is {issuer!r}; expected type 'Role' and arn "
                f"{dev_role_arn!r} (the role this check assumed)"
            )

        assert record["managementEvent"] is False, (
            f"{op}: managementEvent is {record.get('managementEvent')!r}, expected False: {shown}"
        )
        assert record["eventCategory"] == "Data", (
            f"{op}: eventCategory is {record.get('eventCategory')!r}, expected 'Data'. AWS lists "
            f"all five identity-pool operations here as data events: {shown}"
        )
        resources = record.get("resources") or []
        assert resources and resources[0].get("type") == _POOL_RESOURCE_TYPE, (
            f"{op}: resources[0] is {resources[:1]!r}; expected type {_POOL_RESOURCE_TYPE!r} -- "
            f"the value the selector matched on"
        )
        assert resources[0].get("ARN") == pool_arn, (
            f"{op}: resources[0].ARN is {resources[0].get('ARN')!r}, expected {pool_arn!r}"
        )

        # The logins map: kept, keyed by provider, every value redacted.
        params = record.get("requestParameters") or {}
        logins = params.get("logins")
        expected_provider = developer_provider if op == _SIGNED_OP else provider_name
        assert isinstance(logins, dict) and sorted(logins) == [expected_provider], (
            f"{op}: requestParameters.logins is {logins!r}; expected a map keyed by exactly "
            f"[{expected_provider!r}] (the provider the call presented): {shown}"
        )
        assert all(v == _REDACTED for v in logins.values()), (
            f"{op}: requestParameters.logins values are {list(logins.values())!r}; every value "
            f"must be the literal {_REDACTED!r}"
        )
        dumped = json.dumps(record)
        assert call["id_token"] not in dumped, (
            f"{op}: the live Cognito ID token (prefix {call['id_token'][:12]!r}) appears in the "
            f"delivered log file {key!r} -- a credential in an audit log"
        )

        if op == "GetCredentialsForIdentity":
            creds = (record.get("responseElements") or {}).get("credentials")
            assert isinstance(creds, dict), (
                f"{op}: responseElements.credentials is {creds!r}: {shown}"
            )
            missing = [k for k in ("accessKeyId", "sessionToken", "expiration") if k not in creds]
            assert not missing, (
                f"{op}: responseElements.credentials lacks {missing!r}; it has {sorted(creds)!r}"
            )
            assert call["secret"] not in dumped, (
                f"{op}: the vended SecretKey appears in the delivered record {key!r}"
            )
        if op == "GetOpenIdToken":
            elements = record.get("responseElements") or {}
            assert elements.get("identityId") == call["identity_id"], (
                f"{op}: responseElements.identityId is {elements.get('identityId')!r}, expected "
                f"{call['identity_id']!r}: {shown}"
            )
            assert "token" not in elements, (
                f"{op}: responseElements carries a `token` member ({sorted(elements)!r}); the "
                f"OpenID token is a bearer credential and is omitted from the record"
            )
            assert call["token"] not in dumped, (
                f"{op}: the minted OpenID token appears in the delivered record {key!r}"
            )

    # Event history is management-only: none of the five appear, but CreateIdentityPool does.
    history = []
    control = []
    t_index = time.monotonic()
    while True:
        history = _lookup_all(
            ct,
            LookupAttributes=[{
                "AttributeKey": "EventSource",
                "AttributeValue": "cognito-identity.amazonaws.com",
            }],
            StartTime=window_start - datetime.timedelta(minutes=5),
            EndTime=datetime.datetime.now(datetime.timezone.utc),
        )
        control = [
            ev for ev in history
            if ev.get("EventName") == "CreateIdentityPool" and pool_id in ev.get("CloudTrailEvent", "")
        ]
        if control or time.monotonic() - t_index > _INDEX_CEILING_S:
            break
        time.sleep(_POLL_S)
    assert control, (
        f"event history has no CreateIdentityPool record for {pool_id!r} after "
        f"{time.monotonic() - t_index + waited:.0f}s; it is the management-event control the "
        f"absence below rests on. {len(history)} cognito-identity events were returned: "
        f"{sorted({ev.get('EventName') for ev in history})!r}"
    )
    data_in_history = [
        (ev.get("EventName"), ev.get("EventId"))
        for ev in history
        if ev.get("EventName") in _ALL_OPS
        and (pool_id in ev.get("CloudTrailEvent", "")
             or any(i in ev.get("CloudTrailEvent", "") for i in identity_ids))
    ]
    assert data_in_history == [], (
        f"{len(data_in_history)} identity-pool DATA event(s) appear in LookupEvents: "
        f"{data_in_history[:6]!r}. Event history holds management events only; these same calls "
        f"are demonstrably data events (delivered above with eventCategory 'Data'), and this "
        f"pool's CreateIdentityPool is present in the same result"
    )

    # Teardown in the body: the bucket drain can outlast the cleanup time budget.
    _delete_trail_idempotent(ct, trail_name)
    _drain_and_delete_bucket(s3, bucket)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
