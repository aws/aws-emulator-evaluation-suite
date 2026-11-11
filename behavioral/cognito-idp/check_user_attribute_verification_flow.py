"""user-attribute-verification-flow."""

from __future__ import annotations

import io
import json
import re
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "user-attribute-verification-flow"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]

_UPDATE_SOURCE = "CustomEmailSender_UpdateUserAttribute"
# GetUserAttributeVerificationCode is documented only as "sends a code to verify the attribute";
# the trigger-source table lists both attribute sources, so a resend is accepted under either.
_RESEND_SOURCES = ("CustomEmailSender_VerifyUserAttribute", _UPDATE_SOURCE)


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:eventing",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """UpdateUserAttributes on email leaves it pending unverified; GetUserAttributeVerificationCode
    resends a working code; VerifyUserAttribute rejects a wrong code with CodeMismatchException and
    marks the attribute verified with the real code (captured via a CustomEmailSender trigger).

    Reference: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-custom-email-sender.html
    """
    idp = ctx.client("cognito-idp")
    sqs = ctx.client("sqs")
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    kms = ctx.client("kms")
    sts = ctx.client("sts")

    # One run-wide deadline, anchored BEFORE the slow setup; every wait below is bounded by it
    # rather than adding its own independent time on top.
    run_deadline = time.monotonic() + 600.0

    resource_tags = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
    ident = sts.get_caller_identity()
    account = ident["Account"]
    partition = ident["Arn"].split(":")[1]

    # --- symmetric KMS key Cognito encrypts the codes with ---
    # The root statement delegates key access to IAM, which is how the Lambda role's own inline
    # kms:Decrypt below takes effect. Naming the seconds-old role in the key policy instead can be
    # rejected as an invalid principal before IAM propagates it. cognito-idp needs Encrypt, plus
    # CreateGrant for the one-time grant UpdateUserPool/CreateUserPool creates on the key.
    key_arn = kms.create_key(
        Description="sim2real-behav cognito custom email sender code key",
        KeySpec="SYMMETRIC_DEFAULT",
        KeyUsage="ENCRYPT_DECRYPT",
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "AccountRoot",
                        "Effect": "Allow",
                        "Principal": {"AWS": f"arn:{partition}:iam::{account}:root"},
                        "Action": "kms:*",
                        "Resource": "*",
                    },
                    {
                        "Sid": "CognitoEncryptsCodes",
                        "Effect": "Allow",
                        "Principal": {"Service": "cognito-idp.amazonaws.com"},
                        "Action": ["kms:Encrypt", "kms:CreateGrant"],
                        "Resource": "*",
                        "Condition": {"StringEquals": {"aws:SourceAccount": account}},
                    },
                ],
            }
        ),
        Tags=[{"TagKey": k, "TagValue": v} for k, v in resource_tags.items()],
    )["KeyMetadata"]["Arn"]
    ctx.on_cleanup(
        lambda: kms.schedule_key_deletion(KeyId=key_arn, PendingWindowInDays=7)
    )

    # --- SQS sink the trigger ships each decrypted code to ---
    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-verifcode-"), tags=resource_tags
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]

    # --- execution role: kms:Decrypt on the key + sqs:SendMessage on the sink, and nothing else.
    # No logs permissions, so the function can never create a /aws/lambda/<fn> log group that
    # would outlive the check.
    role_name = ctx.unique_name("sim2real-cog-trigger-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "lambda.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
        Tags=[{"Key": k, "Value": v} for k, v in resource_tags.items()],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="decrypt-and-send",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "kms:Decrypt", "Resource": key_arn},
                    {
                        "Effect": "Allow",
                        "Action": "sqs:SendMessage",
                        "Resource": queue_arn,
                    },
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: _safe_delete_role_policy(iam, role_name, "decrypt-and-send"))

    # --- the CustomEmailSender function ---
    # A custom sender is the only way to see the real code: a CustomMessage trigger receives only
    # the "{####}" placeholder. Cognito passes the code ESDK-encrypted under the pool's KMS key.
    function_name = ctx.unique_name("sim2real-cog-trigger-")
    function_arn = _retry_create_function(
        lam,
        run_deadline,
        FunctionName=function_name,
        Runtime="nodejs22.x",
        Role=role_arn,
        Handler="index.handler",
        Code={"ZipFile": _build_lambda_zip("index.mjs", _SENDER_JS)},
        Environment={"Variables": {"SIM2REAL_QUEUE_URL": queue_url}},
        Timeout=60,
        MemorySize=256,
        Tags=resource_tags,
    )
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=function_name))
    function_state = _poll_until(
        lambda: lam.get_function_configuration(FunctionName=function_name)["State"],
        lambda state: state in ("Active", "Failed"),
        deadline=run_deadline,
        timeout_s=90.0,
        interval_s=2.0,
    )
    assert function_state == "Active", (
        f"lambda function must reach Active before cognito can invoke it, got {function_state!r}"
    )

    # --- user pool wired to the sender + the key ---
    pool = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-pool-"),
        AutoVerifiedAttributes=["email"],
        LambdaConfig={
            "CustomEmailSender": {"LambdaVersion": "V1_0", "LambdaArn": function_arn},
            "KMSKeyID": key_arn,
        },
        UserPoolTags=resource_tags,
    )["UserPool"]
    pool_id, pool_arn = pool["Id"], pool["Arn"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    lam.add_permission(
        FunctionName=function_name,
        StatementId="cognito-idp-invoke",
        Action="lambda:InvokeFunction",
        Principal="cognito-idp.amazonaws.com",
        SourceArn=pool_arn,
    )
    ctx.on_cleanup(
        lambda: lam.remove_permission(
            FunctionName=function_name, StatementId="cognito-idp-invoke"
        )
    )

    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-client-"),
        ExplicitAuthFlows=[
            "ALLOW_ADMIN_USER_PASSWORD_AUTH",
            "ALLOW_REFRESH_TOKEN_AUTH",
        ],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(
        lambda: idp.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id)
    )

    inbox = _CodeInbox(sqs, queue_url)

    # Two users: one is spent on the wrong-code probe, the other carries the happy path. Cognito
    # rate-limits VerifyUserAttribute per user after a failed attempt (LimitExceededException).
    wrong_user, wrong_token = _provision_user(ctx, idp, pool_id, client_id)
    good_user, good_token = _provision_user(ctx, idp, pool_id, client_id)
    new_email = f"{good_user}-new@example.com"

    # --- negative leg, on the throwaway user, against its REAL outstanding code ---
    _call_with_backoff(
        lambda: idp.update_user_attributes(
            AccessToken=wrong_token,
            UserAttributes=[
                {"Name": "email", "Value": f"{wrong_user}-new@example.com"}
            ],
        ),
        run_deadline,
    )
    real_code = inbox.next_code(wrong_user, (_UPDATE_SOURCE,), run_deadline)
    assert re.fullmatch(r"\d{6}", real_code), (
        f"decrypted verification code is not 6 digits: {real_code!r}"
    )
    wrong_code = _wrong_code(real_code)
    code_mismatch, mismatch_message = _wrong_code_error(
        idp, wrong_token, "email", wrong_code, run_deadline
    )
    assert code_mismatch == "CodeMismatchException", (
        f"an incorrect code must not verify, got {code_mismatch!r}"
    )
    assert mismatch_message == "Invalid verification code provided, please try again.", (
        f"CodeMismatchException message, got {mismatch_message!r}"
    )
    wrong_attrs = {
        a["Name"]: a["Value"]
        for a in idp.admin_get_user(UserPoolId=pool_id, Username=wrong_user)[
            "UserAttributes"
        ]
    }
    assert wrong_attrs["email_verified"] == "false", (
        f"a rejected code must leave the attribute unverified, got {wrong_attrs!r}"
    )

    # --- happy path, on a user that has never failed a verification attempt ---
    _call_with_backoff(
        lambda: idp.update_user_attributes(
            AccessToken=good_token,
            UserAttributes=[{"Name": "email", "Value": new_email}],
        ),
        run_deadline,
    )
    # Consume the UpdateUserAttributes delivery so the next delivery for this user is the resend.
    first_code = inbox.next_code(good_user, (_UPDATE_SOURCE,), run_deadline)
    assert re.fullmatch(r"\d{6}", first_code), (
        f"decrypted verification code is not 6 digits: {first_code!r}"
    )

    attrs = {
        a["Name"]: a["Value"]
        for a in idp.admin_get_user(UserPoolId=pool_id, Username=good_user)[
            "UserAttributes"
        ]
    }
    assert attrs["email"] == new_email
    assert attrs["email_verified"] == "false", (
        "attribute should be pending/unverified after change"
    )

    # The explicit resend. Real Cognito may resend the SAME code while it is still valid rather
    # than rotate it, so the resent code is not required to differ -- it must simply be the one
    # VerifyUserAttribute accepts.
    # Only a delivery that ARRIVES after the resend request counts: Lambda delivery is at-least-once,
    # so a duplicate of the UpdateUserAttribute delivery already buffered would otherwise be read as
    # the resent code and the resend leg would pass without a resend ever being observed.
    resend_requested_at = time.time()
    _call_with_backoff(
        lambda: idp.get_user_attribute_verification_code(
            AccessToken=good_token, AttributeName="email"
        ),
        run_deadline,
    )
    second_code = inbox.next_code(
        good_user, _RESEND_SOURCES, run_deadline, after=resend_requested_at
    )
    assert re.fullmatch(r"\d{6}", second_code), (
        f"decrypted verification code is not 6 digits: {second_code!r}"
    )

    # ONE verify with the real code. LimitExceededException (a throttle) is absorbed with bounded
    # backoff, but a CodeMismatchException on the real code is the defect and is NOT retried:
    # retrying would spend the user's attempt budget.
    _call_with_backoff(
        lambda: idp.verify_user_attribute(
            AccessToken=good_token, AttributeName="email", Code=second_code
        ),
        run_deadline,
    )

    attrs_final = {
        a["Name"]: a["Value"]
        for a in idp.admin_get_user(UserPoolId=pool_id, Username=good_user)[
            "UserAttributes"
        ]
    }
    assert attrs_final["email"] == new_email, (
        f"the verified email changed unexpectedly: {attrs_final!r}"
    )
    assert attrs_final["email_verified"] == "true", (
        f"the real resent code did not verify the attribute: {attrs_final!r}"
    )


# The CustomEmailSender function. It parses the AWS Encryption SDK message Cognito puts
# in request.code, KMS-decrypts the data key under the message encryption context, derives the
# content key per the algorithm suite, authenticates the header, decrypts every frame and ships
# {userName, triggerSource, type, code, ok} to SQS. A decrypt failure ships ok=false + the error.
_SENDER_JS = r"""
import { KMSClient, DecryptCommand } from "@aws-sdk/client-kms";
import { SQSClient, SendMessageCommand } from "@aws-sdk/client-sqs";
import crypto from "node:crypto";

const kms = new KMSClient({});
const sqs = new SQSClient({});

// suite id -> [data key bytes, HKDF digest or null, committing]
const SUITES = {
  0x0014: [16, null, false], 0x0046: [24, null, false], 0x0078: [32, null, false],
  0x0114: [16, "sha256", false], 0x0146: [24, "sha256", false], 0x0178: [32, "sha256", false],
  0x0214: [16, "sha256", false], 0x0346: [24, "sha384", false], 0x0378: [32, "sha384", false],
  0x0478: [32, "sha512", true], 0x0578: [32, "sha512", true],
};

async function retryDenied(fn) {
  // The execution role is seconds old: IAM may not have propagated kms:Decrypt/sqs:SendMessage.
  let last;
  for (let i = 0; i < 25; i++) {
    try { return await fn(); } catch (e) {
      if (!String(e && e.name).includes("AccessDenied")) throw e;
      last = e; await new Promise(r => setTimeout(r, 1000));
    }
  }
  throw last;
}

function gcmDecrypt(alg, key, iv, aad, ct, tag) {
  const d = crypto.createDecipheriv(alg, key, iv, { authTagLength: 16 });
  d.setAAD(aad); d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]);
}

async function decryptCode(b64) {
  const buf = Buffer.from(b64, "base64");
  let off = 0;
  const u8 = () => buf.readUInt8(off++);
  const u16 = () => { const v = buf.readUInt16BE(off); off += 2; return v; };
  const u32 = () => { const v = buf.readUInt32BE(off); off += 4; return v; };
  const u64 = () => { const v = Number(buf.readBigUInt64BE(off)); off += 8; return v; };
  const take = n => { const v = buf.subarray(off, off + n); off += n; return v; };

  const version = u8();
  if (version === 0x01) { const t = u8(); if (t !== 0x80) throw new Error("bad v1 type " + t); }
  else if (version !== 0x02) throw new Error("unknown ESDK message version " + version);
  const suiteId = u16();
  const suite = SUITES[suiteId];
  if (!suite) throw new Error("unsupported algorithm suite 0x" + suiteId.toString(16));
  const [keyLen, digest, committing] = suite;
  const messageId = take(version === 0x01 ? 16 : 32);
  const aadLen = u16();
  const ec = {};
  if (aadLen > 0) {
    const pairs = u16();
    for (let i = 0; i < pairs; i++) {
      const k = take(u16()).toString("utf8"); ec[k] = take(u16()).toString("utf8");
    }
  }
  const edks = [];
  const edkCount = u16();
  for (let i = 0; i < edkCount; i++) {
    edks.push({ provider: take(u16()).toString("utf8"), info: take(u16()).toString("utf8"),
                blob: Buffer.from(take(u16())) });
  }
  const contentType = u8();
  let ivLen = 12, frameLen, commitment = null;
  if (version === 0x01) { take(4); ivLen = u8(); frameLen = u32(); }
  else { frameLen = u32(); commitment = take(32); }
  const headerBody = buf.subarray(0, off);
  const headerIv = version === 0x01 ? take(ivLen) : Buffer.alloc(12);
  const headerTag = take(16);

  const edk = edks.find(e => e.provider === "aws-kms");
  if (!edk) throw new Error("no aws-kms encrypted data key in " + JSON.stringify(edks.map(e => e.provider)));
  const dk = await retryDenied(() => kms.send(new DecryptCommand({
    CiphertextBlob: edk.blob, EncryptionContext: ec, KeyId: edk.info })));
  const dataKey = Buffer.from(dk.Plaintext);

  let key;
  const sid = Buffer.alloc(2); sid.writeUInt16BE(suiteId);
  if (committing) {
    key = Buffer.from(crypto.hkdfSync(digest, dataKey, messageId,
                                      Buffer.concat([sid, Buffer.from("DERIVEKEY")]), keyLen));
    const ck = Buffer.from(crypto.hkdfSync(digest, dataKey, messageId, Buffer.from("COMMITKEY"), 32));
    if (!crypto.timingSafeEqual(ck, commitment)) throw new Error("key commitment mismatch");
  } else if (digest) {
    key = Buffer.from(crypto.hkdfSync(digest, dataKey, Buffer.alloc(0),
                                      Buffer.concat([sid, messageId]), keyLen));
  } else {
    key = dataKey;
  }
  const alg = "aes-" + (keyLen * 8) + "-gcm";
  gcmDecrypt(alg, key, headerIv, headerBody, Buffer.alloc(0), headerTag);  // header auth

  const aadFor = (label, seq, len) => {
    const s = Buffer.alloc(4); s.writeUInt32BE(seq);
    const l = Buffer.alloc(8); l.writeBigUInt64BE(BigInt(len));
    return Buffer.concat([messageId, Buffer.from(label), s, l]);
  };
  const parts = [];
  if (contentType === 0x02) {
    for (;;) {
      let seq = u32();
      if (seq === 0xFFFFFFFF) {
        seq = u32(); const iv = take(ivLen); const len = u32(); const ct = take(len); const tag = take(16);
        parts.push(gcmDecrypt(alg, key, iv, aadFor("AWSKMSEncryptionClient Final Frame", seq, len), ct, tag));
        break;
      }
      const iv = take(ivLen); const ct = take(frameLen); const tag = take(16);
      parts.push(gcmDecrypt(alg, key, iv, aadFor("AWSKMSEncryptionClient Frame", seq, frameLen), ct, tag));
    }
  } else if (contentType === 0x01) {
    const iv = take(ivLen); const len = u64(); const ct = take(len); const tag = take(16);
    parts.push(gcmDecrypt(alg, key, iv, aadFor("AWSKMSEncryptionClient Single Block", 1, len), ct, tag));
  } else {
    throw new Error("unknown content type " + contentType);
  }
  return { code: Buffer.concat(parts).toString("utf8"), version, suite: suiteId,
           keyArn: edk.info, ecKeys: Object.keys(ec).sort() };
}

export const handler = async (event) => {
  const req = event.request || {};
  const out = { triggerSource: event.triggerSource, userName: event.userName,
                userPoolId: event.userPoolId, type: req.type || null,
                email: (req.userAttributes || {}).email || null,
                clientMetadata: req.clientMetadata || null, receivedAt: Date.now() };
  try { Object.assign(out, await decryptCode(req.code)); out.ok = true; }
  catch (e) { out.ok = false; out.error = String((e && e.stack) || e); }
  await retryDenied(() => sqs.send(new SendMessageCommand({
    QueueUrl: process.env.SIM2REAL_QUEUE_URL, MessageBody: JSON.stringify(out) })));
};
"""


def _provision_user(ctx, idp, pool_id: str, client_id: str):
    """Create a confirmed user with a verified email and return (username, access token).

    MessageAction=SUPPRESS, so AdminCreateUser invokes no sender and leaves nothing on the queue."""
    username = ctx.unique_name("sim2real-user-")
    password = "Str0ng!Passw0rd"
    idp.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        UserAttributes=[
            {"Name": "email", "Value": f"{username}-orig@example.com"},
            {"Name": "email_verified", "Value": "true"},
        ],
        MessageAction="SUPPRESS",
    )
    ctx.on_cleanup(lambda: idp.admin_delete_user(UserPoolId=pool_id, Username=username))
    idp.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=password, Permanent=True
    )
    access_token = idp.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )["AuthenticationResult"]["AccessToken"]
    return username, access_token


def _wrong_code(code: str) -> str:
    """A code of the same shape as the real one that differs from it in every digit."""
    return "".join(str((int(c) + 5) % 10) if c.isdigit() else c for c in code)


def _poll_until(probe, predicate, deadline, timeout_s=60.0, interval_s=2.0):
    end = min(deadline, time.monotonic() + timeout_s)
    last = None
    while time.monotonic() < end:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"poll did not satisfy predicate within {timeout_s}s: last value {last!r}"
    )


def _build_lambda_zip(filename: str, source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, source)
    return buf.getvalue()


def _retry_create_function(lam, deadline, timeout_s=90.0, **kwargs):
    """CreateFunction, retrying only while a brand-new role is not yet assumable by Lambda."""
    end = min(deadline, time.monotonic() + timeout_s)
    while True:
        try:
            return lam.create_function(**kwargs)["FunctionArn"]
        except ClientError as exc:
            if (
                exc.response["Error"]["Code"] != "InvalidParameterValueException"
                or time.monotonic() > end
            ):
                raise
            time.sleep(3.0)


def _call_with_backoff(fn, deadline, base_delay=3.0, max_delay=20.0):
    """Call fn(), absorbing LimitExceededException with bounded exponential
    backoff, never sleeping past the given time.monotonic() deadline. Any
    other ClientError is propagated immediately so callers can assert on it."""
    delay = base_delay
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "LimitExceededException":
                raise
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise
            time.sleep(min(delay, remaining))
            delay = min(delay * 2, max_delay)


def _wrong_code_error(idp, access_token, attribute_name, code, deadline):
    """Attempt VerifyUserAttribute with a deliberately-wrong code; return (error code, message).

    Absorbs LimitExceededException with bounded backoff against the shared deadline. Any other
    error -- the expected CodeMismatchException included -- is returned immediately and never
    retried, so a retry can't mask it. An accepted wrong code raises AssertionError."""
    delay = 3.0
    while True:
        try:
            idp.verify_user_attribute(
                AccessToken=access_token, AttributeName=attribute_name, Code=code
            )
        except ClientError as exc:
            err = exc.response["Error"]
            code_name = err["Code"]
            if code_name != "LimitExceededException":
                return code_name, err.get("Message")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return code_name, err.get("Message")
            time.sleep(min(delay, remaining))
            delay = min(delay * 2, 20.0)
            continue
        raise AssertionError(
            "VerifyUserAttribute accepted a deliberately-wrong code; expected CodeMismatchException"
        )


class _CodeInbox:
    """Drains the trigger's SQS sink and hands back the decrypted code for one delivery.

    Deliveries are matched on (userName, triggerSource), so a delivery for the other user, or a
    duplicate Lambda invocation, can never be mistaken for the one asked for. Unmatched deliveries
    are buffered, not dropped. Every wait is bounded by the shared run-wide deadline."""

    def __init__(self, sqs, queue_url: str):
        self.sqs, self.queue_url, self.seen = sqs, queue_url, []

    def next_code(
        self,
        username: str,
        trigger_sources,
        deadline,
        timeout_s: float = 120.0,
        after: float | None = None,
    ) -> str:
        """``after``: accept only deliveries SQS stamped as sent after that epoch instant (seconds).

        Judged on SQS's own SentTimestamp, not on when this client read the message: a duplicate that
        was already sitting in the queue when the resend was requested must not count."""
        end = min(deadline, time.monotonic() + timeout_s)
        while True:
            for i, m in enumerate(self.seen):
                if after is not None and m["_sent_at"] < after:
                    continue
                if (
                    m.get("userName") == username
                    and m.get("triggerSource") in trigger_sources
                ):
                    self.seen.pop(i)
                    assert m.get("ok") is True, (
                        f"the CustomEmailSender trigger could not decrypt request.code: {m.get('error')!r}"
                    )
                    assert m.get("type") == "customEmailSenderRequestV1", (
                        f"unexpected custom email sender request type: {m.get('type')!r}"
                    )
                    return m["code"]
            remaining = end - time.monotonic()
            if remaining <= 0:
                break
            resp = self.sqs.receive_message(
                QueueUrl=self.queue_url,
                MaxNumberOfMessages=10,
                WaitTimeSeconds=max(0, min(5, int(remaining))),
                AttributeNames=["SentTimestamp"],
            )
            for raw in resp.get("Messages", []):
                sent_at = int(raw["Attributes"]["SentTimestamp"]) / 1000.0
                self.seen.append({**json.loads(raw["Body"]), "_sent_at": sent_at})
                self.sqs.delete_message(
                    QueueUrl=self.queue_url, ReceiptHandle=raw["ReceiptHandle"]
                )
        raise AssertionError(
            f"no {trigger_sources!r} code for {username!r} reached the trigger's queue within the "
            f"shared check deadline; deliveries seen but unmatched: {self.seen!r}"
        )


def _safe_delete_role_policy(iam, role_name, policy_name):
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
