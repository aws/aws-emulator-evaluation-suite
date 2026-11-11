"""java21-handler-resolution-and-pojo-serde."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import re
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "java21-handler-resolution-and-pojo-serde"
GROUP = 'data-plane'
SERVICES = ['lambda']

WARM_INVOKES = 6

# Two resolution rules in ONE deployment package, and no external dependency for either:
#   probe.H      does NOT implement RequestHandler and takes no Context, so it must be addressed
#                as "probe.H::mainHandler";
#   probe.Iface  DOES implement RequestHandler, so the documented form is the bare "probe.Iface".
# The java21 managed runtime provides aws-lambda-java-core on the classpath, so probe.Iface
# resolves with no lib/ jar at all (unlike org.crac, which it does not provide).
#
# The bytecode is embedded as base64 with its SHA-256 asserted, so the check needs no JDK;
# JAVA_SOURCE below is the readable source of probe.H.
JAVA_SOURCE = r'''
package probe;
public class Order {                                  // touched by H's static initializer
    public static final java.util.List<String> LOG = new java.util.ArrayList<>();
    static { LOG.add("Order.<clinit>"); }
    public static int mark(String s) { LOG.add(s); return LOG.size(); }
}
public class In { public String mode; public int n; public List<String> items; public int holdMs; }
public class H {
    static { Order.mark("H.<clinit>"); }
    static final String INIT_ID = UUID.randomUUID().toString();
    static int ctorCount = 0;
    static int invokeCount = 0;
    public H() { Order.mark("H.<init>"); ctorCount++; }
    public Map<String, Object> mainHandler(In in) {
        invokeCount++;
        System.out.println("PROBE-RAN invoke=" + invokeCount);
        if (in != null && "throw".equals(in.mode))
            throw new IllegalStateException("probe-deliberate-failure");
        // ... reports order/ctorCount/invokeCount/nPlusOne/nClass/items/pojoFields/logStream
    }
}
'''

_SHA256 = {
    "probe/Order.class": "02ef1b4647bdaff11aabd15f6556e07de0fdab0a024797a09fe5dd83e394edd9",
    "probe/In.class": "17d036d34668afa414fec627b2a051e1c73a4d3b1309fee8dfac24290659e56a",
    "probe/H.class": "264638719a6b69d61768bfafd7026d3bc15cd92ea46591acb639ca8b9c46f183",
    "probe/Iface.class": "125a936c925888d916a47fd9c35c1fa7842df51beac382558c8886c939be47bb",
}

_B64 = {  # @@GENERATED@@ probe/Order.class probe/In.class probe/H.class probe/Iface.class
    "probe/Order.class":
        "yv66vgAAAEEAKgoAAgADBwAEDAAFAAYBABBqYXZhL2xhbmcvT2JqZWN0AQAGPGluaXQ+AQADKClWCQAIAAkHAAoMAAsADAEA"
        "C3Byb2JlL09yZGVyAQADTE9HAQAQTGphdmEvdXRpbC9MaXN0OwsADgAPBwAQDAARABIBAA5qYXZhL3V0aWwvTGlzdAEAA2Fk"
        "ZAEAFShMamF2YS9sYW5nL09iamVjdDspWgsADgAUDAAVABYBAARzaXplAQADKClJBwAYAQATamF2YS91dGlsL0FycmF5TGlz"
        "dAoAFwADCAAbAQAOT3JkZXIuPGNsaW5pdD4BAAlTaWduYXR1cmUBACRMamF2YS91dGlsL0xpc3Q8TGphdmEvbGFuZy9TdHJp"
        "bmc7PjsBAARDb2RlAQAPTGluZU51bWJlclRhYmxlAQASTG9jYWxWYXJpYWJsZVRhYmxlAQAEdGhpcwEADUxwcm9iZS9PcmRl"
        "cjsBAARtYXJrAQAVKExqYXZhL2xhbmcvU3RyaW5nOylJAQABcwEAEkxqYXZhL2xhbmcvU3RyaW5nOwEACDxjbGluaXQ+AQAK"
        "U291cmNlRmlsZQEACk9yZGVyLmphdmEAIQAIAAIAAAABABkACwAMAAEAHAAAAAIAHQADAAEABQAGAAEAHgAAAC8AAQABAAAA"
        "BSq3AAGxAAAAAgAfAAAABgABAAAABAAgAAAADAABAAAABQAhACIAAAAJACMAJAABAB4AAAA9AAIAAQAAABOyAAcquQANAgBX"
        "sgAHuQATAQCsAAAAAgAfAAAABgABAAAABwAgAAAADAABAAAAEwAlACYAAAAIACcABgABAB4AAAAyAAIAAAAAABa7ABdZtwAZ"
        "swAHsgAHEhq5AA0CAFexAAAAAQAfAAAACgACAAAABQAKAAYAAQAoAAAAAgAp",
    "probe/In.class":
        "yv66vgAAAEEAGQoAAgADBwAEDAAFAAYBABBqYXZhL2xhbmcvT2JqZWN0AQAGPGluaXQ+AQADKClWBwAIAQAIcHJvYmUvSW4B"
        "AARtb2RlAQASTGphdmEvbGFuZy9TdHJpbmc7AQABbgEAAUkBAAVpdGVtcwEAEExqYXZhL3V0aWwvTGlzdDsBAAlTaWduYXR1"
        "cmUBACRMamF2YS91dGlsL0xpc3Q8TGphdmEvbGFuZy9TdHJpbmc7PjsBAAZob2xkTXMBAARDb2RlAQAPTGluZU51bWJlclRh"
        "YmxlAQASTG9jYWxWYXJpYWJsZVRhYmxlAQAEdGhpcwEACkxwcm9iZS9JbjsBAApTb3VyY2VGaWxlAQAHSW4uamF2YQAhAAcA"
        "AgAAAAQAAQAJAAoAAAABAAsADAAAAAEADQAOAAEADwAAAAIAEAABABEADAAAAAEAAQAFAAYAAQASAAAALwABAAEAAAAFKrcA"
        "AbEAAAACABMAAAAGAAEAAAAEABQAAAAMAAEAAAAFABUAFgAAAAEAFwAAAAIAGA==",
    "probe/H.class":
        "yv66vgAAAEEA3goAAgADBwAEDAAFAAYBABBqYXZhL2xhbmcvT2JqZWN0AQAGPGluaXQ+AQADKClWCAAIAQAISC48aW5pdD4K"
        "AAoACwcADAwADQAOAQALcHJvYmUvT3JkZXIBAARtYXJrAQAVKExqYXZhL2xhbmcvU3RyaW5nOylJCQAQABEHABIMABMAFAEA"
        "B3Byb2JlL0gBAAljdG9yQ291bnQBAAFJCQAQABYMABcAFAEAC2ludm9rZUNvdW50CQAZABoHABsMABwAHQEAEGphdmEvbGFu"
        "Zy9TeXN0ZW0BAANvdXQBABVMamF2YS9pby9QcmludFN0cmVhbTsSAAAAHwwAIAAhAQAXbWFrZUNvbmNhdFdpdGhDb25zdGFu"
        "dHMBABUoSSlMamF2YS9sYW5nL1N0cmluZzsKACMAJAcAJQwAJgAnAQATamF2YS9pby9QcmludFN0cmVhbQEAB3ByaW50bG4B"
        "ABUoTGphdmEvbGFuZy9TdHJpbmc7KVYJACkAKgcAKwwALAAUAQAIcHJvYmUvSW4BAAZob2xkTXMKAC4ALwcAMAwAMQAyAQAQ"
        "amF2YS9sYW5nL1RocmVhZAEABXNsZWVwAQAEKEopVgcANAEAHmphdmEvbGFuZy9JbnRlcnJ1cHRlZEV4Y2VwdGlvbggANgEA"
        "BXRocm93CQApADgMADkAOgEABG1vZGUBABJMamF2YS9sYW5nL1N0cmluZzsKADwAPQcAPgwAPwBAAQAQamF2YS9sYW5nL1N0"
        "cmluZwEABmVxdWFscwEAFShMamF2YS9sYW5nL09iamVjdDspWgcAQgEAH2phdmEvbGFuZy9JbGxlZ2FsU3RhdGVFeGNlcHRp"
        "b24IAEQBABhwcm9iZS1kZWxpYmVyYXRlLWZhaWx1cmUKAEEARgwABQAnBwBIAQAXamF2YS91dGlsL0xpbmtlZEhhc2hNYXAK"
        "AEcAAwgASwEABW9yZGVyBwBNAQATamF2YS91dGlsL0FycmF5TGlzdAkACgBPDABQAFEBAANMT0cBABBMamF2YS91dGlsL0xp"
        "c3Q7CgBMAFMMAAUAVAEAGShMamF2YS91dGlsL0NvbGxlY3Rpb247KVYLAFYAVwcAWAwAWQBaAQANamF2YS91dGlsL01hcAEA"
        "A3B1dAEAOChMamF2YS9sYW5nL09iamVjdDtMamF2YS9sYW5nL09iamVjdDspTGphdmEvbGFuZy9PYmplY3Q7CAATCgBdAF4H"
        "AF8MAGAAYQEAEWphdmEvbGFuZy9JbnRlZ2VyAQAHdmFsdWVPZgEAFihJKUxqYXZhL2xhbmcvSW50ZWdlcjsIABcIAGQBAAZp"
        "bml0SWQJABAAZgwAZwA6AQAHSU5JVF9JRAgAaQEAC2phdmFWZXJzaW9uCABrAQAMamF2YS52ZXJzaW9uCgAZAG0MAG4AbwEA"
        "C2dldFByb3BlcnR5AQAmKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1N0cmluZzsIAHEBAAZ2bU5hbWUIAHMBAAxq"
        "YXZhLnZtLm5hbWUIAHUBAAlsb2dTdHJlYW0IAHcBABpBV1NfTEFNQkRBX0xPR19TVFJFQU1fTkFNRQoAGQB5DAB6AG8BAAZn"
        "ZXRlbnYIADkIAH0BAAhuUGx1c09uZQkAKQB/DACAABQBAAFuCACCAQAGbkNsYXNzCgACAIQMAIUAhgEACGdldENsYXNzAQAT"
        "KClMamF2YS9sYW5nL0NsYXNzOwoAiACJBwCKDACLAIwBAA9qYXZhL2xhbmcvQ2xhc3MBAAdnZXROYW1lAQAUKClMamF2YS9s"
        "YW5nL1N0cmluZzsIAI4BAAVpdGVtcwkAKQCQDACOAFEIAJIBAAlpdGVtQ291bnQLAJQAlQcAlgwAlwCYAQAOamF2YS91dGls"
        "L0xpc3QBAARzaXplAQADKClJCgBMAAMKAIgAmwwAnACdAQARZ2V0RGVjbGFyZWRGaWVsZHMBABwoKVtMamF2YS9sYW5nL3Jl"
        "ZmxlY3QvRmllbGQ7CgCfAIkHAKABABdqYXZhL2xhbmcvcmVmbGVjdC9GaWVsZAsAlACiDACjAEABAANhZGQKAKUApgcApwwA"
        "qACpAQAVamF2YS91dGlsL0NvbGxlY3Rpb25zAQAEc29ydAEAEyhMamF2YS91dGlsL0xpc3Q7KVYIAKsBAApwb2pvRmllbGRz"
        "CACtAQAKSC48Y2xpbml0PgoArwCwBwCxDACyALMBAA5qYXZhL3V0aWwvVVVJRAEACnJhbmRvbVVVSUQBABIoKUxqYXZhL3V0"
        "aWwvVVVJRDsKAK8AtQwAtgCMAQAIdG9TdHJpbmcBAARDb2RlAQAPTGluZU51bWJlclRhYmxlAQASTG9jYWxWYXJpYWJsZVRh"
        "YmxlAQAEdGhpcwEACUxwcm9iZS9IOwEAC21haW5IYW5kbGVyAQAbKExwcm9iZS9JbjspTGphdmEvdXRpbC9NYXA7AQABZgEA"
        "GUxqYXZhL2xhbmcvcmVmbGVjdC9GaWVsZDsBAAJpbgEACkxwcm9iZS9JbjsBAA9MamF2YS91dGlsL01hcDsBAAZmaWVsZHMB"
        "ABZMb2NhbFZhcmlhYmxlVHlwZVRhYmxlAQA1TGphdmEvdXRpbC9NYXA8TGphdmEvbGFuZy9TdHJpbmc7TGphdmEvbGFuZy9P"
        "YmplY3Q7PjsBACRMamF2YS91dGlsL0xpc3Q8TGphdmEvbGFuZy9TdHJpbmc7PjsBAA1TdGFja01hcFRhYmxlBwDJAQAaW0xq"
        "YXZhL2xhbmcvcmVmbGVjdC9GaWVsZDsBAAlTaWduYXR1cmUBAEEoTHByb2JlL0luOylMamF2YS91dGlsL01hcDxMamF2YS9s"
        "YW5nL1N0cmluZztMamF2YS9sYW5nL09iamVjdDs+OwEACDxjbGluaXQ+AQAKU291cmNlRmlsZQEABkguamF2YQEAEEJvb3Rz"
        "dHJhcE1ldGhvZHMIANEBABJQUk9CRS1SQU4gaW52b2tlPQEPBgDTCgDUANUHANYMACAA1wEAJGphdmEvbGFuZy9pbnZva2Uv"
        "U3RyaW5nQ29uY2F0RmFjdG9yeQEAmChMamF2YS9sYW5nL2ludm9rZS9NZXRob2RIYW5kbGVzJExvb2t1cDtMamF2YS9sYW5n"
        "L1N0cmluZztMamF2YS9sYW5nL2ludm9rZS9NZXRob2RUeXBlO0xqYXZhL2xhbmcvU3RyaW5nO1tMamF2YS9sYW5nL09iamVj"
        "dDspTGphdmEvbGFuZy9pbnZva2UvQ2FsbFNpdGU7AQAMSW5uZXJDbGFzc2VzBwDaAQAlamF2YS9sYW5nL2ludm9rZS9NZXRo"
        "b2RIYW5kbGVzJExvb2t1cAcA3AEAHmphdmEvbGFuZy9pbnZva2UvTWV0aG9kSGFuZGxlcwEABkxvb2t1cAAhABAAAgAAAAMA"
        "GABnADoAAAAIABMAFAAAAAgAFwAUAAAAAwABAAUABgABALcAAAA9AAIAAQAAABMqtwABEge4AAlXsgAPBGCzAA+xAAAAAgC4"
        "AAAABgABAAAAEwC5AAAADAABAAAAEwC6ALsAAAABALwAvQACALcAAAN7AAUACAAAAYOyABUEYLMAFbIAGLIAFboAHgAAtgAi"
        "K8YAFiu0ACieAA8rtAAohbgALacABE0rxgAZEjUrtAA3tgA7mQANuwBBWRJDtwBFv7sAR1m3AElNLBJKuwBMWbIATrcAUrkA"
        "VQMAVywSW7IAD7gAXLkAVQMAVywSYrIAFbgAXLkAVQMAVywSY7IAZbkAVQMAVywSaBJquABsuQBVAwBXLBJwEnK4AGy5AFUD"
        "AFcsEnQSdrgAeLkAVQMAVywSeyvHAAcBpwAHK7QAN7kAVQMAVywSfCvHAAcCpwAJK7QAfgRguABcuQBVAwBXLBKBK8cABwGn"
        "ABArtAB+uABctgCDtgCHuQBVAwBXLBKNK8cABwGnAAcrtACPuQBVAwBXLBKRK8YACiu0AI/HAAcCpwAMK7QAj7kAkwEAuABc"
        "uQBVAwBXuwBMWbcAmU4SKbYAmjoEGQS+NgUDNgYVBhUFogAcGQQVBjI6By0ZB7YAnrkAoQIAV4QGAaf/4y24AKQsEqotuQBV"
        "AwBXLLAAAQAhACkALAAzAAQAuAAAAGIAGAAAABYACAAZABYAGgAhABsALQAdAD0AHgBHACAATwAhAGIAIgBxACMAgAAkAIwA"
        "JQCaACYAqAAnALYAKADLACkA5QAqAQMAKwEYACwBPAAtAUQALgFzAC8BdwAwAYEAMQC5AAAANAAFAWEADAC+AL8ABwAAAYMA"
        "ugC7AAAAAAGDAMAAwQABAE8BNAAcAMIAAgFEAD8AwwBRAAMAxAAAABYAAgBPATQAHADFAAIBRAA/AMMAxgADAMcAAAEgABBs"
        "BwAzABn/AHkAAwcAEAcAKQcAVgACBwBWBwA8/wADAAMHABAHACkHAFYAAwcAVgcAPAcAAv8AEAADBwAQBwApBwBWAAIHAFYH"
        "ADz/AAUAAwcAEAcAKQcAVgADBwBWBwA8Af8AEwADBwAQBwApBwBWAAIHAFYHADz/AAwAAwcAEAcAKQcAVgADBwBWBwA8BwAC"
        "/wAQAAMHABAHACkHAFYAAgcAVgcAPP8AAwADBwAQBwApBwBWAAMHAFYHADwHAAL/ABMAAwcAEAcAKQcAVgACBwBWBwA8/wAD"
        "AAMHABAHACkHAFYAAgcAVgcAPP8ACAADBwAQBwApBwBWAAMHAFYHADwB/wAfAAcHABAHACkHAFYHAJQHAMgBAQAA+AAfAMoA"
        "AAACAMsACADMAAYAAQC3AAAAPAABAAAAAAAYEqy4AAlXuACutgC0swBlA7MADwOzABWxAAAAAQC4AAAAEgAEAAAADQAGAA8A"
        "DwAQABMAEQADAM0AAAACAM4AzwAAAAgAAQDSAAEA0ADYAAAACgABANkA2wDdABk=",
    "probe/Iface.class":
        "yv66vgAAAEEATwoAAgADBwAEDAAFAAYBABBqYXZhL2xhbmcvT2JqZWN0AQAGPGluaXQ+AQADKClWBwAIAQAXamF2YS91dGls"
        "L0xpbmtlZEhhc2hNYXAKAAcAAwgACwEAA3ZpYQgADQEADlJlcXVlc3RIYW5kbGVyCwAPABAHABEMABIAEwEADWphdmEvdXRp"
        "bC9NYXABAANwdXQBADgoTGphdmEvbGFuZy9PYmplY3Q7TGphdmEvbGFuZy9PYmplY3Q7KUxqYXZhL2xhbmcvT2JqZWN0OwgA"
        "FQEACG5QbHVzT25lCQAXABgHABkMABoAGwEACHByb2JlL0luAQABbgEAAUkKAB0AHgcAHwwAIAAhAQARamF2YS9sYW5nL0lu"
        "dGVnZXIBAAd2YWx1ZU9mAQAWKEkpTGphdmEvbGFuZy9JbnRlZ2VyOwgAIwEACWxvZ1N0cmVhbQsAJQAmBwAnDAAoACkBAC1j"
        "b20vYW1hem9uYXdzL3NlcnZpY2VzL2xhbWJkYS9ydW50aW1lL0NvbnRleHQBABBnZXRMb2dTdHJlYW1OYW1lAQAUKClMamF2"
        "YS9sYW5nL1N0cmluZzsIACsBAAptZW1MaW1pdE1iCwAlAC0MAC4ALwEAEmdldE1lbW9yeUxpbWl0SW5NQgEAAygpSQoAMQAy"
        "BwAzDAA0ADUBAAtwcm9iZS9JZmFjZQEADWhhbmRsZVJlcXVlc3QBAEooTHByb2JlL0luO0xjb20vYW1hem9uYXdzL3NlcnZp"
        "Y2VzL2xhbWJkYS9ydW50aW1lL0NvbnRleHQ7KUxqYXZhL3V0aWwvTWFwOwcANwEANGNvbS9hbWF6b25hd3Mvc2VydmljZXMv"
        "bGFtYmRhL3J1bnRpbWUvUmVxdWVzdEhhbmRsZXIBAARDb2RlAQAPTGluZU51bWJlclRhYmxlAQASTG9jYWxWYXJpYWJsZVRh"
        "YmxlAQAEdGhpcwEADUxwcm9iZS9JZmFjZTsBAAJpbgEACkxwcm9iZS9JbjsBAANjdHgBAC9MY29tL2FtYXpvbmF3cy9zZXJ2"
        "aWNlcy9sYW1iZGEvcnVudGltZS9Db250ZXh0OwEAA291dAEAD0xqYXZhL3V0aWwvTWFwOwEAFkxvY2FsVmFyaWFibGVUeXBl"
        "VGFibGUBADVMamF2YS91dGlsL01hcDxMamF2YS9sYW5nL1N0cmluZztMamF2YS9sYW5nL09iamVjdDs+OwEADVN0YWNrTWFw"
        "VGFibGUHAEcBABBqYXZhL2xhbmcvU3RyaW5nAQAJU2lnbmF0dXJlAQBwKExwcm9iZS9JbjtMY29tL2FtYXpvbmF3cy9zZXJ2"
        "aWNlcy9sYW1iZGEvcnVudGltZS9Db250ZXh0OylMamF2YS91dGlsL01hcDxMamF2YS9sYW5nL1N0cmluZztMamF2YS9sYW5n"
        "L09iamVjdDs+OwEAVShMamF2YS9sYW5nL09iamVjdDtMY29tL2FtYXpvbmF3cy9zZXJ2aWNlcy9sYW1iZGEvcnVudGltZS9D"
        "b250ZXh0OylMamF2YS9sYW5nL09iamVjdDsBABBNZXRob2RQYXJhbWV0ZXJzAQCJTGphdmEvbGFuZy9PYmplY3Q7TGNvbS9h"
        "bWF6b25hd3Mvc2VydmljZXMvbGFtYmRhL3J1bnRpbWUvUmVxdWVzdEhhbmRsZXI8THByb2JlL0luO0xqYXZhL3V0aWwvTWFw"
        "PExqYXZhL2xhbmcvU3RyaW5nO0xqYXZhL2xhbmcvT2JqZWN0Oz47PjsBAApTb3VyY2VGaWxlAQAKSWZhY2UuamF2YQAhADEA"
        "AgABADYAAAADAAEABQAGAAEAOAAAAC8AAQABAAAABSq3AAGxAAAAAgA5AAAABgABAAAADAA6AAAADAABAAAABQA7ADwAAAAB"
        "ADQANQACADgAAAD5AAQABAAAAFC7AAdZtwAJTi0SChIMuQAOAwBXLRIUK8cABwKnAAkrtAAWBGC4ABy5AA4DAFctEiIsuQAk"
        "AQC5AA4DAFctEiosuQAsAQC4ABy5AA4DAFctsAAAAAQAOQAAABoABgAAAA4ACAAPABMAEAAtABEAPAASAE4AEwA6AAAAKgAE"
        "AAAAUAA7ADwAAAAAAFAAPQA+AAEAAABQAD8AQAACAAgASABBAEIAAwBDAAAADAABAAgASABBAEQAAwBFAAAANQAC/wAeAAQH"
        "ADEHABcHACUHAA8AAgcADwcARv8ABQAEBwAxBwAXBwAlBwAPAAMHAA8HAEYBAEgAAAACAEkQQQA0AEoAAgA4AAAANAADAAMA"
        "AAAKKivAABcstgAwsAAAAAIAOQAAAAYAAQAAAAwAOgAAAAwAAQAAAAoAOwA8AAAASwAAAAkCAAAQAAAAEAAAAgBIAAAAAgBM"
        "AE0AAAACAE4=",
}

# The exact ordering the JLS mandates: Order.<clinit> runs because H.<clinit> touches Order, so it
# completes FIRST; H.<clinit> completes next; only then is the handler instance constructed.
EXPECTED_ORDER = ["Order.<clinit>", "H.<clinit>", "H.<init>"]

# probe.H.mainHandler's own frame, with a line number from the bytecode's LineNumberTable. The line
# number is not pinned (an edit to the pinned source would move it); the frame's shape is.
_FRAME = re.compile(r"^probe\.H\.mainHandler\(H\.java:[0-9]+\)$")


# ===== helpers =====
def _deployment_zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for arc, b64 in _B64.items():
            raw = base64.b64decode(b64)
            got = hashlib.sha256(raw).hexdigest()
            assert got == _SHA256[arc], (
                f"embedded artifact {arc!r} is sha256 {got!r}, pinned {_SHA256[arc]!r} — the "
                f"bytecode under test is not the bytecode this check was verified against"
            )
            zf.writestr(arc, raw)
    return buf.getvalue()


_EXEC_ROLES = {}


def _exec_role_arn(ctx):
    """An execution role this check creates, shared by every function it deploys."""
    cached = _EXEC_ROLES.get(id(ctx))
    if cached is not None and cached[0] is ctx:
        return cached[1]
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    _EXEC_ROLES[id(ctx)] = (ctx, arn)
    return arn


def _create_function(lam, kwargs, timeout_s=90):
    """CreateFunction, retried while a freshly created role is not yet assumable by Lambda."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            propagating = (
                err.get("Code") == "InvalidParameterValueException"
                and "cannot be assumed by Lambda" in err.get("Message", "")
            )
            if not propagating or time.monotonic() >= deadline:
                raise
            time.sleep(3.0)


def _cleanup_fn(ctx, lam, name):
    try:
        # Deleting the function deletes every published version and any snapshot with it.
        lam.delete_function(FunctionName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    # /aws/lambda/<fn> is created by the service, and buffered log delivery can recreate it after a
    # successful delete_log_group, so require a sustained absence.
    logs = ctx.client("logs")
    group = f"/aws/lambda/{name}"
    absent = 0
    for _ in range(20):
        present = any(
            g["logGroupName"] == group
            for g in logs.describe_log_groups(logGroupNamePrefix=group)["logGroups"]
        )
        if present:
            absent = 0
            try:
                logs.delete_log_group(logGroupName=group)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            absent += 1
            if absent >= 3:
                return
        time.sleep(3)
    raise RuntimeError(f"log group {group} still reappearing after 20 delete passes")


def _poll(probe, timeout_s, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        got = probe()
        if got:
            return got
        time.sleep(interval_s)
    return None


def _wait_active(lam, fn, timeout_s=300):
    def _probe():
        cfg = lam.get_function_configuration(FunctionName=fn)
        if cfg["State"] == "Failed":
            raise AssertionError(f"{fn} entered State=Failed: {cfg.get('StateReason')!r}")
        if cfg["State"] == "Active" and cfg.get("LastUpdateStatus") in (None, "Successful"):
            return cfg
        return None

    cfg = _poll(_probe, timeout_s)
    assert cfg is not None, f"{fn} did not reach State=Active within {timeout_s}s"
    return cfg


def _raw_invoke(lam, fn, payload):
    resp = lam.invoke(
        FunctionName=fn, LogType="Tail", Payload=json.dumps(payload).encode()
    )
    raw = resp["Payload"].read()
    assert resp["StatusCode"] == 200, f"{fn}: StatusCode {resp['StatusCode']!r} {raw!r}"
    log = base64.b64decode(resp["LogResult"]).decode("utf8", "replace")
    return resp.get("FunctionError"), json.loads(raw), log


def _ok(lam, fn, payload):
    err, body, log = _raw_invoke(lam, fn, payload)
    assert err is None, f"{fn} invoke of {payload!r} failed: FunctionError={err!r} payload={body!r}"
    return body, log


def _err(lam, fn, payload):
    err, body, log = _raw_invoke(lam, fn, payload)
    assert err == "Unhandled", (
        f"{fn} invoke of {payload!r} was expected to fail with FunctionError=='Unhandled' but "
        f"returned FunctionError={err!r} and payload {body!r}"
    )
    return body, log


def _set_handler(lam, fn, handler):
    lam.update_function_configuration(FunctionName=fn, Handler=handler)
    cfg = _wait_active(lam, fn)
    assert cfg["Handler"] == handler, f"Handler did not round-trip: {cfg['Handler']!r} != {handler!r}"
    return cfg


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """The Java 21 runtime loads the bytecode, runs static init in JLS order, reuses one handler
    instance per sandbox (counters climb per INIT_ID), binds JSON into a typed POJO, resolves both
    handler-string forms, and reports exceptions and binding failures with one handler instance."""
    lam = ctx.client("lambda")
    fn = ctx.unique_name("sim2real-behav-javahandler-")
    _create_function(lam, dict(
        FunctionName=fn, Runtime="java21", Handler="probe.H::mainHandler",
        Role=_exec_role_arn(ctx), Code={"ZipFile": _deployment_zip()}, MemorySize=512, Timeout=30,
        Tags={"sim2real": "true"},
    ))
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, fn))
    _wait_active(lam, fn)

    # ---- N sequential invokes: one instance per sandbox, counted per sandbox ---------------
    bodies = []
    for i in range(WARM_INVOKES):
        body, _ = _ok(lam, fn, {"mode": "ok", "n": 3, "items": ["a", "b"], "unknownField": "zzz"})
        bodies.append(body)

    first = bodies[0]
    assert first["javaVersion"].startswith("21."), (
        f"java.version was {first['javaVersion']!r}; a java21 runtime must report 21.x, and nothing "
        f"below is about a JVM if this is not one"
    )
    assert first["vmName"] == "OpenJDK 64-Bit Server VM", (
        f"java.vm.name was {first['vmName']!r}, not the HotSpot server VM the runtime ships"
    )
    # Lambda may recycle a sandbox at any time, so the static INIT_ID (minted once per class load)
    # keys every per-sandbox claim; the counters are compared within one INIT_ID only.
    sandboxes: dict = {}
    for b in bodies:
        sandboxes.setdefault(b["initId"], []).append(b)
    for init_id, served in sandboxes.items():
        assert len({b["logStream"] for b in served}) == 1, (
            f"one sandbox (INIT_ID {init_id}) reported log streams "
            f"{sorted({b['logStream'] for b in served})!r}; a sandbox owns one log stream"
        )
        assert [b["invokeCount"] for b in served] == list(range(1, len(served) + 1)), (
            f"the static invocation counter of sandbox {init_id} did not climb 1..{len(served)}: "
            f"{[b['invokeCount'] for b in served]!r}"
        )
    assert len(sandboxes) < WARM_INVOKES, (
        f"each of the {WARM_INVOKES} sequential invocations reported a new INIT_ID "
        f"{sorted(sandboxes)!r}: the class was re-loaded every time, so no sandbox was reused"
    )
    seen = {init_id: (served[-1]["logStream"], served[-1]["invokeCount"])
            for init_id, served in sandboxes.items()}
    assert all(b["ctorCount"] == 1 for b in bodies), (
        f"the handler class must be constructed exactly ONCE per execution environment and that "
        f"instance reused for every invocation; ctorCount across {WARM_INVOKES} invocations was "
        f"{[b['ctorCount'] for b in bodies]!r}"
    )
    assert all(b["order"] == EXPECTED_ORDER for b in bodies), (
        f"static initialization did not run in JLS 12.4.1 order. Expected {EXPECTED_ORDER!r} — "
        f"Order.<clinit> completes first because H.<clinit> touches Order, then H.<clinit>, then "
        f"the constructor — but the runtime produced {[b['order'] for b in bodies]!r}. The list is "
        f"appended to by the customer's own initializers, so this is the ordering the JVM chose"
    )

    # ---- typed POJO deserialization, not a passthrough -----------------------------------
    assert first["nPlusOne"] == 4, (
        f"the JSON number 3 was not bound to the POJO's `int n`: the handler computed n+1 = "
        f"{first['nPlusOne']!r}, expected 4. A passthrough hands the handler a string and this is "
        f"either '31' or an error"
    )
    assert first["nClass"] == "java.lang.Integer", (
        f"the deserialized `n` boxed to {first['nClass']!r}, not java.lang.Integer"
    )
    assert first["items"] == ["a", "b"] and first["itemCount"] == 2, (
        f"the JSON array did not bind to List<String>: items={first['items']!r} "
        f"itemCount={first['itemCount']!r}"
    )
    assert first["pojoFields"] == ["holdMs", "items", "mode", "n"], (
        f"reflection over the POJO under test reported fields {first['pojoFields']!r}; the class "
        f"whose bytecode this check pinned declares holdMs/items/mode/n"
    )
    assert "unknownField" not in first, (
        f"the response carries a key for the unknown JSON member the request sent, so the payload "
        f"was echoed rather than bound to the POJO: {sorted(first)!r}"
    )
    # An unknown member is DROPPED, not rejected: the invoke above already succeeded, which is the
    # assertion. Confirm the same payload without it is otherwise identical in the bound fields.
    lean, _ = _ok(lam, fn, {"mode": "ok", "n": 3, "items": ["a", "b"]})
    assert (lean["nPlusOne"], lean["items"]) == (first["nPlusOne"], first["items"]), (
        f"dropping the unknown member changed the bound fields: {lean!r} vs {first!r}"
    )
    # The runtime's Jackson configuration coerces a JSON string "3" into the POJO's int.
    coerced, _ = _ok(lam, fn, {"n": "3"})
    assert coerced["nPlusOne"] == 4 and coerced["nClass"] == "java.lang.Integer", (
        f"the runtime's Jackson configuration coerces the JSON string \"3\" into the POJO's int "
        f"(as on AWS); it produced nPlusOne={coerced['nPlusOne']!r} "
        f"nClass={coerced['nClass']!r}"
    )
    assert "mode" not in coerced and "items" not in coerced, (
        f"unsupplied POJO fields stayed null and the runtime's serializer omits null map values, so "
        f"neither key may appear: {sorted(coerced)!r}"
    )

    # ---- failure arm A: a Java exception keeps its identity and its stack frame ------------
    thrown, thrown_log = _err(lam, fn, {"mode": "throw", "n": 1})
    assert thrown["errorType"] == "java.lang.IllegalStateException", (
        f"the error payload's errorType was {thrown.get('errorType')!r}; a Throwable from customer "
        f"Java code must be reported under its fully-qualified Java class"
    )
    assert thrown["errorMessage"] == "probe-deliberate-failure", (
        f"errorMessage was {thrown.get('errorMessage')!r}, not the exception's own message"
    )
    assert thrown["stackTrace"] and _FRAME.match(thrown["stackTrace"][0]), (
        f"stackTrace[0] was {(thrown.get('stackTrace') or [None])[0]!r}; the topmost frame must be "
        f"probe.H.mainHandler(H.java:<line>) — a source file name and a line number that only the "
        f"bytecode's LineNumberTable can supply"
    )
    assert "PROBE-RAN" in thrown_log, (
        f"customer code did not run before throwing, so the arm proves nothing about a Java "
        f"exception: {thrown_log[:400]!r}"
    )
    # Control: a sandbox that served the exception keeps its handler instance and its counter.
    after, _ = _ok(lam, fn, {"mode": "ok", "n": 3})
    assert after["ctorCount"] == 1, (
        f"the invocation after a handler exception reported ctorCount={after['ctorCount']!r}; the "
        f"handler instance is constructed once per sandbox"
    )
    if after["initId"] in seen:
        stream, count = seen[after["initId"]]
        assert after["logStream"] == stream and after["invokeCount"] > count, (
            f"sandbox {after['initId']} continued after the exception on logStream "
            f"{after['logStream']!r} with invokeCount {after['invokeCount']!r}; it was {stream!r} "
            f"at count {count!r}"
        )

    # ---- failure arm B: a POJO binding failure is a parse error, not a handler error -------
    unbindable, unbindable_log = _err(lam, fn, {"n": "abc"})
    assert unbindable["errorType"] == "java.lang.RuntimeException", (
        f"a value that cannot bind to the POJO's int reported errorType "
        f"{unbindable.get('errorType')!r}; real AWS reports java.lang.RuntimeException here "
        f"rather than the Jackson exception class and not a handler exception"
    )
    assert unbindable["errorMessage"] == "An error occurred during JSON parsing", (
        f"errorMessage was {unbindable.get('errorMessage')!r}"
    )
    assert unbindable["stackTrace"] == [], (
        f"a deserialization failure carries an EMPTY stackTrace in the payload — the frames are "
        f"the runtime's, not the customer's, so they are withheld; got "
        f"{unbindable['stackTrace']!r}"
    )
    assert "PROBE-RAN" not in unbindable_log.split("START RequestId")[-1], (
        f"the handler body executed despite the payload failing to bind, so deserialization is not "
        f"happening before dispatch: {unbindable_log[-600:]!r}"
    )
    survivor, _ = _ok(lam, fn, {"n": 7})
    assert survivor["nPlusOne"] == 8 and survivor["ctorCount"] == 1, (
        f"a deserialization failure destroyed the environment: the control invocation returned "
        f"{survivor!r}"
    )

    # ---- the second resolution rule: a RequestHandler implementor, addressed bare ----------
    _set_handler(lam, fn, "probe.Iface")
    iface, _ = _ok(lam, fn, {"n": 41})
    assert iface["via"] == "RequestHandler", (
        f"the bare class name resolved to something other than the RequestHandler path: {iface!r}"
    )
    assert iface["nPlusOne"] == 42, (
        f"the RequestHandler path did not bind the POJO: {iface!r}"
    )
    assert iface["memLimitMb"] == 512, (
        f"the injected Context reported memoryLimitInMB={iface['memLimitMb']!r}, not the "
        f"function's configured 512 — this path takes a Context and the runtime must populate it"
    )
    # The "::method" form is also accepted for a class that implements RequestHandler; the docs
    # specify the bare form for that case and do not say the other is refused.
    _set_handler(lam, fn, "probe.Iface::handleRequest")
    iface_explicit, _ = _ok(lam, fn, {"n": 41})
    assert iface_explicit["via"] == "RequestHandler" and iface_explicit["nPlusOne"] == 42, (
        f"the explicit '::handleRequest' form on a RequestHandler implementor did not resolve; real "
        f"AWS accepts it: {iface_explicit!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
