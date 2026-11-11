"""ruby-vendor-bundle-gem-resolves-via-gem-path."""

from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = 'ruby-vendor-bundle-gem-resolves-via-gem-path'
GROUP = 'packaging'
SERVICES = ['lambda']

_RUNTIME = "ruby3.3"
_API_VERSION = "3.3.0"
_GEM_NAME = "sim2real_vendor_gem"
_GEM_VERSION = "1.0.0"

_GEM_LIB = (
    'module Sim2realVendorGem\n'
    f'  VERSION = "{_GEM_VERSION}"\n'
    '  def self.greet\n'
    '    "vendored-ok"\n'
    '  end\n'
    'end\n'
)

_GEMSPEC = (
    '# -*- encoding: utf-8 -*-\n'
    f'# stub: {_GEM_NAME} {_GEM_VERSION} ruby lib\n\n'
    'Gem::Specification.new do |s|\n'
    f'  s.name = "{_GEM_NAME}".freeze\n'
    f'  s.version = "{_GEM_VERSION}".freeze\n'
    '  s.require_paths = ["lib".freeze]\n'
    '  s.authors = ["sim2real".freeze]\n'
    '  s.summary = "vendored test gem".freeze\n'
    f'  s.files = ["lib/{_GEM_NAME}.rb".freeze]\n'
    'end\n'
)

_HANDLER = (
    f'require "{_GEM_NAME}"\n\n'
    'def handler(event:, context:)\n'
    '  spec = Gem.loaded_specs["%s"]\n' % _GEM_NAME
    + '  {"greet" => Sim2realVendorGem.greet, "version" => Sim2realVendorGem::VERSION,\n'
    '   "full_gem_path" => spec && spec.full_gem_path}\n'
    'end\n'
)

_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})
_BASIC_EXEC = "arn:{partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"


def _partition(ctx) -> str:
    """The session's partition, so an ARN names the partition the check runs in."""
    return ctx.client("sts").get_caller_identity()["Arn"].split(":")[1]
_ROLE_NOT_READY = "The role defined for the function cannot be assumed by Lambda."


def _teardown(undo, *not_found):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` means gone."""

    def run_undo():
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _reap_log_groups(logs, names, *, reads=3, interval_s=4.0, budget_s=40.0):
    """Delete every group in ``names`` until ``reads`` consecutive rounds find all absent.

    A log stream an invocation buffered can flush after the function is deleted and recreate its
    group, so one delete is one round, not a teardown. Raises if a group is still coming back.
    """
    deadline = time.monotonic() + budget_s
    absent = 0
    while absent < reads:
        present = [
            name for name in names
            if any(g["logGroupName"] == name
                   for g in logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"])
        ]
        for name in present:
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        absent = 0 if present else absent + 1
        if absent < reads:
            if time.monotonic() > deadline:
                raise AssertionError(f"log groups {present!r} still present after {budget_s}s")
            time.sleep(interval_s)


_LOG_GROUPS: list = []


def _log_groups(ctx):
    """This run's /aws/lambda group names; one reap, registered before the first function, covers all."""
    for owner, names in _LOG_GROUPS:
        if owner is ctx:
            return names
    names: list = []
    _LOG_GROUPS.append((ctx, names))
    logs = ctx.client("logs")
    # Registered BEFORE any create, so LIFO runs it after every function has been deleted.
    ctx.on_cleanup(lambda: _reap_log_groups(logs, names))
    return names


def _make_zip(entries):
    """A deployment zip with an explicit unix mode on every member."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data, mode in entries:
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = mode << 16
            zf.writestr(info, data.encode() if isinstance(data, str) else data)
    return buf.getvalue()


def _execution_role(ctx):
    """An execution role this check creates and deletes."""
    iam = ctx.client("iam")
    policy_arn = _BASIC_EXEC.format(partition=_partition(ctx))
    name = ctx.unique_name("sim2real-l3-exec-")
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=_TRUST,
                          Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)
    ctx.on_cleanup(_teardown(
        lambda: iam.detach_role_policy(RoleName=name, PolicyArn=policy_arn), "NoSuchEntity"))
    return arn


def _function(ctx, lam, role, label, zipbytes, *, runtime, handler, **extra):
    """Create a function, register its teardown and log-group reap, and wait for State=Active."""
    name = ctx.unique_name(f"sim2real-l3-{label}-")
    _log_groups(ctx).append(f"/aws/lambda/{name}")
    kwargs = dict(FunctionName=name, Runtime=runtime, Handler=handler, Role=role,
                  Code={"ZipFile": zipbytes}, MemorySize=256, Timeout=15,
                  Tags={"sim2real": CHECK})
    kwargs.update(extra)
    deadline = time.monotonic() + 90
    while True:
        try:
            lam.create_function(**kwargs)
            break
        except ClientError as exc:
            err = exc.response["Error"]
            # IAM propagation of the role created above exposes no condition to poll.
            if (err["Code"] != "InvalidParameterValueException"
                    or err["Message"] != _ROLE_NOT_READY or time.monotonic() > deadline):
                raise
            time.sleep(3)
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name),
                             "ResourceNotFoundException"))
    _wait_settled(lam, name)
    return name


def _wait_settled(lam, name, timeout_s=120):
    deadline = time.monotonic() + timeout_s
    while True:
        cfg = lam.get_function_configuration(FunctionName=name)
        assert cfg["State"] != "Failed", f"{name} entered State=Failed: {cfg.get('StateReason')!r}"
        if cfg["State"] == "Active" and cfg.get("LastUpdateStatus") in (None, "Successful"):
            return cfg
        assert time.monotonic() < deadline, (
            f"{name} did not settle within {timeout_s}s: State={cfg['State']!r} "
            f"LastUpdateStatus={cfg.get('LastUpdateStatus')!r}")
        time.sleep(1)


def _invoke(lam, name, payload):
    resp = lam.invoke(FunctionName=name, Payload=json.dumps(payload).encode())
    return resp.get("FunctionError"), resp["Payload"].read()


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A gem vendored under vendor/bundle/ruby/<api-version>/{specifications,gems} on arm64 is
    resolved through GEM_PATH by an ordinary ``require``: the same handler source with no
    vendor/bundle directory instead fails to load the gem at all.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/ruby-package.html
    """
    lam = ctx.client("lambda")
    role = _execution_role(ctx)

    vendored_zip = _make_zip([
        ("lambda_function.rb", _HANDLER, 0o100644),
        (f"vendor/bundle/ruby/{_API_VERSION}/specifications/{_GEM_NAME}-{_GEM_VERSION}.gemspec",
         _GEMSPEC, 0o100644),
        (f"vendor/bundle/ruby/{_API_VERSION}/gems/{_GEM_NAME}-{_GEM_VERSION}/lib/{_GEM_NAME}.rb",
         _GEM_LIB, 0o100644),
    ])
    fn = _function(ctx, lam, role, "vgem", vendored_zip, runtime=_RUNTIME,
                   handler="lambda_function.handler", Architectures=["arm64"])
    err, raw = _invoke(lam, fn, {})
    assert err is None, f"vendored gem invoke failed: FunctionError={err!r}, payload {raw!r}"
    body = json.loads(raw)
    assert body["greet"] == "vendored-ok", f"the vendored gem's own method returned {body!r}"
    assert body["version"] == _GEM_VERSION, f"the vendored gem's VERSION constant read {body!r}"
    expected_gem_dir = f"/var/task/vendor/bundle/ruby/{_API_VERSION}/gems/{_GEM_NAME}-{_GEM_VERSION}"
    assert body["full_gem_path"] == expected_gem_dir, (
        f"RubyGems activated the gem from {body['full_gem_path']!r}, expected {expected_gem_dir!r}")

    bare_zip = _make_zip([("lambda_function.rb", _HANDLER, 0o100644)])
    bare_fn = _function(ctx, lam, role, "bare", bare_zip, runtime=_RUNTIME,
                        handler="lambda_function.handler", Architectures=["arm64"])
    bare_err, bare_raw = _invoke(lam, bare_fn, {})
    assert bare_err == "Unhandled", (
        f"the same handler with no vendor/bundle directory must fail to load; "
        f"FunctionError={bare_err!r}, payload {bare_raw!r}")
    bare_doc = json.loads(bare_raw)
    assert bare_doc["errorType"] == "Init<LoadError>", (
        f"expected Init<LoadError> with no vendor/bundle, got {bare_doc['errorType']!r}")
    assert bare_doc["errorMessage"] == f"cannot load such file -- {_GEM_NAME}", (
        f"expected the interpreter's own LoadError message, got {bare_doc['errorMessage']!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
