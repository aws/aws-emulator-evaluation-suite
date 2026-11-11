"""ruby-layer-gem-under-ruby-gems-version-resolves."""

from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = 'ruby-layer-gem-under-ruby-gems-version-resolves'
GROUP = 'packaging'
SERVICES = ['lambda']

_RUNTIME = "ruby4.0"
_API_VERSION = "4.0.0"
_GEM_NAME = "sim2real_layer_gem"
_GEM_VERSION = "2.0.0"

_GEM_LIB = (
    'module Sim2realLayerGem\n'
    f'  VERSION = "{_GEM_VERSION}"\n'
    '  def self.greet\n'
    '    "layer-ok"\n'
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
    '  s.summary = "layer test gem".freeze\n'
    f'  s.files = ["lib/{_GEM_NAME}.rb".freeze]\n'
    'end\n'
)

_HANDLER = (
    f'require "{_GEM_NAME}"\n\n'
    'def handler(event:, context:)\n'
    '  spec = Gem.loaded_specs["%s"]\n' % _GEM_NAME
    + '  {"greet" => Sim2realLayerGem.greet, "version" => Sim2realLayerGem::VERSION,\n'
    '   "full_gem_path" => spec && spec.full_gem_path,\n'
    '   "gem_path" => ENV["GEM_PATH"].to_s.split(":")}\n'
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
    """Delete every group in ``names`` until ``reads`` consecutive rounds find all absent."""
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
    for owner, names in _LOG_GROUPS:
        if owner is ctx:
            return names
    names: list = []
    _LOG_GROUPS.append((ctx, names))
    logs = ctx.client("logs")
    ctx.on_cleanup(lambda: _reap_log_groups(logs, names))
    return names


def _make_zip(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data, mode in entries:
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = mode << 16
            zf.writestr(info, data.encode() if isinstance(data, str) else data)
    return buf.getvalue()


def _execution_role(ctx):
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


def _publish_layer(ctx, lam, zipbytes, *, compatible_runtimes):
    name = ctx.unique_name("sim2real-l3-layer-")
    published = lam.publish_layer_version(
        LayerName=name, Content={"ZipFile": zipbytes},
        CompatibleRuntimes=compatible_runtimes,
        Description="sim2real " + CHECK,
    )
    arn = published["LayerVersionArn"]
    ctx.on_cleanup(_teardown(
        lambda: lam.delete_layer_version(LayerName=name, VersionNumber=published["Version"]),
        "ResourceNotFoundException"))
    return arn


def _function(ctx, lam, role, label, zipbytes, *, runtime, handler, **extra):
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
    """A gem published in a layer under ruby/gems/<api-version>/{specifications,gems} is resolved
    through GEM_PATH by an ordinary ``require``, with its directory placed in GEM_PATH after the
    function's own vendor/bundle entry; the same handler deployed without the layer fails to load.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/ruby-package.html#ruby-layers
    """
    lam = ctx.client("lambda")
    role = _execution_role(ctx)

    layer_zip = _make_zip([
        (f"ruby/gems/{_API_VERSION}/specifications/{_GEM_NAME}-{_GEM_VERSION}.gemspec",
         _GEMSPEC, 0o100644),
        (f"ruby/gems/{_API_VERSION}/gems/{_GEM_NAME}-{_GEM_VERSION}/lib/{_GEM_NAME}.rb",
         _GEM_LIB, 0o100644),
    ])
    layer_arn = _publish_layer(ctx, lam, layer_zip, compatible_runtimes=[_RUNTIME])

    handler_zip = _make_zip([("lambda_function.rb", _HANDLER, 0o100644)])
    fn = _function(ctx, lam, role, "lgem", handler_zip, runtime=_RUNTIME,
                   handler="lambda_function.handler", Layers=[layer_arn],
                   Architectures=["x86_64"])
    err, raw = _invoke(lam, fn, {})
    assert err is None, f"layer gem invoke failed: FunctionError={err!r}, payload {raw!r}"
    body = json.loads(raw)
    assert body["greet"] == "layer-ok", f"the layer gem's own method returned {body!r}"
    assert body["version"] == _GEM_VERSION, f"the layer gem's VERSION constant read {body!r}"
    expected_gem_dir = f"/opt/ruby/gems/{_API_VERSION}/gems/{_GEM_NAME}-{_GEM_VERSION}"
    assert body["full_gem_path"] == expected_gem_dir, (
        f"RubyGems activated the layer gem from {body['full_gem_path']!r}, expected "
        f"{expected_gem_dir!r}")
    vendor_entry = f"/var/task/vendor/bundle/ruby/{_API_VERSION}"
    layer_entry = f"/opt/ruby/gems/{_API_VERSION}"
    assert vendor_entry in body["gem_path"] and layer_entry in body["gem_path"], (
        f"GEM_PATH must include both the function's own vendor/bundle entry and the layer's "
        f"ruby/gems/{_API_VERSION} directory; got {body['gem_path']!r}")
    assert body["gem_path"].index(vendor_entry) < body["gem_path"].index(layer_entry), (
        f"the layer's gem directory must be placed in GEM_PATH after the function's own "
        f"vendor/bundle entry; got {body['gem_path']!r}")

    no_layer_fn = _function(ctx, lam, role, "nolayer", handler_zip, runtime=_RUNTIME,
                            handler="lambda_function.handler", Architectures=["x86_64"])
    no_layer_err, no_layer_raw = _invoke(lam, no_layer_fn, {})
    assert no_layer_err == "Unhandled", (
        f"the same handler deployed without the layer must fail to load; "
        f"FunctionError={no_layer_err!r}, payload {no_layer_raw!r}")
    no_layer_doc = json.loads(no_layer_raw)
    assert no_layer_doc["errorType"] == "Init<LoadError>", (
        f"expected Init<LoadError> with the layer detached, got {no_layer_doc['errorType']!r}")
    assert no_layer_doc["errorMessage"] == f"cannot load such file -- {_GEM_NAME}", (
        f"expected the interpreter's own LoadError message, got {no_layer_doc['errorMessage']!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
