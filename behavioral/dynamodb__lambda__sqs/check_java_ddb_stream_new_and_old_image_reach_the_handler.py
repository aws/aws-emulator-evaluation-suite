"""java-ddb-stream-new-and-old-image-reach-the-handler."""
from __future__ import annotations

import base64
import hashlib
import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "java-ddb-stream-new-and-old-image-reach-the-handler"
GROUP = "event-propagation"
SERVICES = ["dynamodb", "lambda", "sqs"]

# com.amazonaws.services.lambda.runtime.RequestHandler<Map<String,Object>, Void>: a DynamoDB
# stream record reaches the handler as nested generic Maps (no DynamodbEvent POJO), and the
# handler walks dynamodb.Keys, dynamodb.NewImage and dynamodb.OldImage by hand and relays each
# record as JSON to an SQS queue the check owns, signing the SendMessage call itself (no AWS
# SDK bundled) so the check can verify the image lifecycle (INSERT only-new, MODIFY both,
# REMOVE only-old).
_SHA256 = "50b068dfe539ff4f2fd9bb88a900cec0b6d4ac476804fef71cbf646e4bd65eb4"

_B64 = (  # @@GENERATED@@ probe/DdbStreamHandler.class
    "yv66vgAAAEEBnQoAAgADBwAEDAAFAAYBABBqYXZhL2xhbmcvT2JqZWN0AQAGPGluaXQ+AQADKClWBwAIAQAXamF2YS9sYW5n"
    "L1N0cmluZ0J1aWxkZXIKAAcAAwgACwEABCUwMngKAA0ADgcADwwAEAARAQAOamF2YS9sYW5nL0J5dGUBAAd2YWx1ZU9mAQAT"
    "KEIpTGphdmEvbGFuZy9CeXRlOwoAEwAUBwAVDAAWABcBABBqYXZhL2xhbmcvU3RyaW5nAQAGZm9ybWF0AQA5KExqYXZhL2xh"
    "bmcvU3RyaW5nO1tMamF2YS9sYW5nL09iamVjdDspTGphdmEvbGFuZy9TdHJpbmc7CgAHABkMABoAGwEABmFwcGVuZAEALShM"
    "amF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9TdHJpbmdCdWlsZGVyOwoABwAdDAAeAB8BAAh0b1N0cmluZwEAFCgpTGph"
    "dmEvbGFuZy9TdHJpbmc7CAAhAQAKSG1hY1NIQTI1NgoAIwAkBwAlDAAmACcBABBqYXZheC9jcnlwdG8vTWFjAQALZ2V0SW5z"
    "dGFuY2UBACYoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZheC9jcnlwdG8vTWFjOwcAKQEAH2phdmF4L2NyeXB0by9zcGVjL1Nl"
    "Y3JldEtleVNwZWMKACgAKwwABQAsAQAXKFtCTGphdmEvbGFuZy9TdHJpbmc7KVYKACMALgwALwAwAQAEaW5pdAEAFihMamF2"
    "YS9zZWN1cml0eS9LZXk7KVYJADIAMwcANAwANQA2AQAhamF2YS9uaW8vY2hhcnNldC9TdGFuZGFyZENoYXJzZXRzAQAFVVRG"
    "XzgBABpMamF2YS9uaW8vY2hhcnNldC9DaGFyc2V0OwoAEwA4DAA5ADoBAAhnZXRCeXRlcwEAHihMamF2YS9uaW8vY2hhcnNl"
    "dC9DaGFyc2V0OylbQgoAIwA8DAA9AD4BAAdkb0ZpbmFsAQAGKFtCKVtCCABAAQAHU0hBLTI1NgoAQgBDBwBEDAAmAEUBABtq"
    "YXZhL3NlY3VyaXR5L01lc3NhZ2VEaWdlc3QBADEoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL3NlY3VyaXR5L01lc3NhZ2VE"
    "aWdlc3Q7CgBCAEcMAEgAPgEABmRpZ2VzdAoASgBLBwBMDABNAE4BABZwcm9iZS9EZGJTdHJlYW1IYW5kbGVyAQADaGV4AQAW"
    "KFtCKUxqYXZhL2xhbmcvU3RyaW5nOwoABwBQDAAaAFEBABwoQylMamF2YS9sYW5nL1N0cmluZ0J1aWxkZXI7CgATAFMMAFQA"
    "VQEABmxlbmd0aAEAAygpSQoAEwBXDABYAFkBAAZjaGFyQXQBAAQoSSlDCABbAQACXCIIAF0BAAJcXAgAXwEAAlxuCABhAQAC"
    "XHIIAGMBAAJcdAgAZQEABlx1JTA0eAoAZwBoBwBpDAAQAGoBABFqYXZhL2xhbmcvSW50ZWdlcgEAFihJKUxqYXZhL2xhbmcv"
    "SW50ZWdlcjsIAGwBAARudWxsBwBuAQANamF2YS91dGlsL01hcAsAbQBwDABxAHIBAAhlbnRyeVNldAEAESgpTGphdmEvdXRp"
    "bC9TZXQ7CwB0AHUHAHYMAHcAeAEADWphdmEvdXRpbC9TZXQBAAhpdGVyYXRvcgEAFigpTGphdmEvdXRpbC9JdGVyYXRvcjsL"
    "AHoAewcAfAwAfQB+AQASamF2YS91dGlsL0l0ZXJhdG9yAQAHaGFzTmV4dAEAAygpWgsAegCADACBAIIBAARuZXh0AQAUKClM"
    "amF2YS9sYW5nL09iamVjdDsHAIQBABNqYXZhL3V0aWwvTWFwJEVudHJ5CwCDAIYMAIcAggEABmdldEtleQoASgCJDACKAIsB"
    "AApqc29uU3RyaW5nAQAuKExqYXZhL2xhbmcvU3RyaW5nQnVpbGRlcjtMamF2YS9sYW5nL1N0cmluZzspVgsAgwCNDACOAIIB"
    "AAhnZXRWYWx1ZQoASgCQDACRAJIBAAlqc29uVmFsdWUBAC4oTGphdmEvbGFuZy9TdHJpbmdCdWlsZGVyO0xqYXZhL2xhbmcv"
    "T2JqZWN0OylWBwCUAQAOamF2YS91dGlsL0xpc3QLAJMAdQcAlwEAEWphdmEvbGFuZy9Cb29sZWFuCgACAB0HAJoBABBqYXZh"
    "L2xhbmcvTnVtYmVyCACcAQARQVdTX0FDQ0VTU19LRVlfSUQKAJ4AnwcAoAwAoQCiAQAQamF2YS9sYW5nL1N5c3RlbQEABmdl"
    "dGVudgEAJihMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9TdHJpbmc7CACkAQAVQVdTX1NFQ1JFVF9BQ0NFU1NfS0VZ"
    "CACmAQARQVdTX1NFU1NJT05fVE9LRU4IAKgBAApBV1NfUkVHSU9OEgAAAKoMAKsAogEAF21ha2VDb25jYXRXaXRoQ29uc3Rh"
    "bnRzCACtAQALIlF1ZXVlVXJsIjoIAK8BAA8sIk1lc3NhZ2VCb2R5IjoKAEoAsQwAsgCiAQAJc2hhMjU2aGV4CAC0AQAUeXl5"
    "eU1NZGQnVCdISG1tc3MnWicKALYAtwcAuAwAuQC6AQAiamF2YS90aW1lL2Zvcm1hdC9EYXRlVGltZUZvcm1hdHRlcgEACW9m"
    "UGF0dGVybgEAOChMamF2YS9sYW5nL1N0cmluZzspTGphdmEvdGltZS9mb3JtYXQvRGF0ZVRpbWVGb3JtYXR0ZXI7CQC8AL0H"
    "AL4MAL8AwAEAFGphdmEvdGltZS9ab25lT2Zmc2V0AQADVVRDAQAWTGphdmEvdGltZS9ab25lT2Zmc2V0OwoAtgDCDADDAMQB"
    "AAh3aXRoWm9uZQEAOChMamF2YS90aW1lL1pvbmVJZDspTGphdmEvdGltZS9mb3JtYXQvRGF0ZVRpbWVGb3JtYXR0ZXI7CADG"
    "AQAIeXl5eU1NZGQKAMgAyQcAygwAywDMAQARamF2YS90aW1lL0luc3RhbnQBAANub3cBABUoKUxqYXZhL3RpbWUvSW5zdGFu"
    "dDsKALYAzgwAFgDPAQA5KExqYXZhL3RpbWUvdGVtcG9yYWwvVGVtcG9yYWxBY2Nlc3NvcjspTGphdmEvbGFuZy9TdHJpbmc7"
    "EgABANEMAKsA0gEASihMamF2YS9sYW5nL1N0cmluZztMamF2YS9sYW5nL1N0cmluZztMamF2YS9sYW5nL1N0cmluZzspTGph"
    "dmEvbGFuZy9TdHJpbmc7CADUAQA+Y29udGVudC10eXBlO2hvc3Q7eC1hbXotZGF0ZTt4LWFtei1zZWN1cml0eS10b2tlbjt4"
    "LWFtei10YXJnZXQSAAIA0RIAAwDXDACrANgBADgoTGphdmEvbGFuZy9TdHJpbmc7TGphdmEvbGFuZy9TdHJpbmc7KUxqYXZh"
    "L2xhbmcvU3RyaW5nOxIABADREgAFAKoKAEoA3AwA3QDeAQAEaG1hYwEAGChbQkxqYXZhL2xhbmcvU3RyaW5nOylbQggA4AEA"
    "A3NxcwgA4gEADGF3czRfcmVxdWVzdBIABgDkDACrAOUBAFwoTGphdmEvbGFuZy9TdHJpbmc7TGphdmEvbGFuZy9TdHJpbmc7"
    "TGphdmEvbGFuZy9TdHJpbmc7TGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvU3RyaW5nOwcA5wEADGphdmEvbmV0L1VS"
    "TBIABwCqCgDmAOoMAAUA6wEAFShMamF2YS9sYW5nL1N0cmluZzspVgoA5gDtDADuAO8BAA5vcGVuQ29ubmVjdGlvbgEAGigp"
    "TGphdmEvbmV0L1VSTENvbm5lY3Rpb247BwDxAQAgamF2YXgvbmV0L3NzbC9IdHRwc1VSTENvbm5lY3Rpb24IAPMBAARQT1NU"
    "CgDwAPUMAPYA6wEAEHNldFJlcXVlc3RNZXRob2QKAPAA+AwA+QD6AQALc2V0RG9PdXRwdXQBAAQoWilWCAD8AQAMQ29udGVu"
    "dC1UeXBlCAD+AQAaYXBwbGljYXRpb24veC1hbXotanNvbi0xLjAKAPABAAwBAQECAQASc2V0UmVxdWVzdFByb3BlcnR5AQAn"
    "KExqYXZhL2xhbmcvU3RyaW5nO0xqYXZhL2xhbmcvU3RyaW5nOylWCAEEAQAKWC1BbXotRGF0ZQgBBgEAFFgtQW16LVNlY3Vy"
    "aXR5LVRva2VuCAEIAQAMWC1BbXotVGFyZ2V0CAEKAQAVQW1hem9uU1FTLlNlbmRNZXNzYWdlCAEMAQANQXV0aG9yaXphdGlv"
    "bgoA8AEODAEPARABABtzZXRGaXhlZExlbmd0aFN0cmVhbWluZ01vZGUBAAQoSSlWCgDwARIMARMBFAEAD2dldE91dHB1dFN0"
    "cmVhbQEAGCgpTGphdmEvaW8vT3V0cHV0U3RyZWFtOwoBFgEXBwEYDAEZARoBABRqYXZhL2lvL091dHB1dFN0cmVhbQEABXdy"
    "aXRlAQAFKFtCKVYKARYBHAwBHQAGAQAFY2xvc2UHAR8BABNqYXZhL2xhbmcvVGhyb3dhYmxlCgEeASEMASIBIwEADWFkZFN1"
    "cHByZXNzZWQBABgoTGphdmEvbGFuZy9UaHJvd2FibGU7KVYKAPABJQwBJgBVAQAPZ2V0UmVzcG9uc2VDb2RlCgDwASgMASkB"
    "KgEADmdldElucHV0U3RyZWFtAQAXKClMamF2YS9pby9JbnB1dFN0cmVhbTsKAPABLAwBLQEqAQAOZ2V0RXJyb3JTdHJlYW0H"
    "AS8BAB1qYXZhL2lvL0J5dGVBcnJheU91dHB1dFN0cmVhbQoBLgADCgEyATMHATQMATUBNgEAE2phdmEvaW8vSW5wdXRTdHJl"
    "YW0BAARyZWFkAQAFKFtCKUkKAS4BOAwBGQE5AQAHKFtCSUkpVgcBOwEAGmphdmEvbGFuZy9SdW50aW1lRXhjZXB0aW9uCAE9"
    "AQAFVVRGLTgKAS4BPwwAHgCiEgAIAUEMAKsBQgEAJyhJTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvU3RyaW5nOwoB"
    "OgDqCAFFAQART0JTRVJWRV9RVUVVRV9VUkwIAUcBAAdSZWNvcmRzCwBtAUkMAUoBSwEAA2dldAEAJihMamF2YS9sYW5nL09i"
    "amVjdDspTGphdmEvbGFuZy9PYmplY3Q7CAFNAQAIZHluYW1vZGIIAU8BAAwiZXZlbnROYW1lIjoIAVEBAAlldmVudE5hbWUI"
    "AVMBAAgsImtleXMiOggBVQEABEtleXMIAVcBAAwsIm5ld0ltYWdlIjoIAVkBAAhOZXdJbWFnZQgBWwEADCwib2xkSW1hZ2Ui"
    "OggBXQEACE9sZEltYWdlCgBKAV8MAWABAgEAC3NlbmRNZXNzYWdlBwFiAQATamF2YS9sYW5nL0V4Y2VwdGlvbggBZAEAJWZh"
    "aWxlZCB0byByZXBvcnQgc3RyZWFtIHJlY29yZCB0byBTUVMKAToBZgwABQFnAQAqKExqYXZhL2xhbmcvU3RyaW5nO0xqYXZh"
    "L2xhbmcvVGhyb3dhYmxlOylWCgBKAWkMAWoBawEADWhhbmRsZVJlcXVlc3QBAFAoTGphdmEvdXRpbC9NYXA7TGNvbS9hbWF6"
    "b25hd3Mvc2VydmljZXMvbGFtYmRhL3J1bnRpbWUvQ29udGV4dDspTGphdmEvbGFuZy9Wb2lkOwcBbQEANGNvbS9hbWF6b25h"
    "d3Mvc2VydmljZXMvbGFtYmRhL3J1bnRpbWUvUmVxdWVzdEhhbmRsZXIBAARDb2RlAQAPTGluZU51bWJlclRhYmxlAQANU3Rh"
    "Y2tNYXBUYWJsZQcBcgEAAltCAQAKRXhjZXB0aW9ucwcBdQEALWNvbS9hbWF6b25hd3Mvc2VydmljZXMvbGFtYmRhL3J1bnRp"
    "bWUvQ29udGV4dAEACVNpZ25hdHVyZQEAdihMamF2YS91dGlsL01hcDxMamF2YS9sYW5nL1N0cmluZztMamF2YS9sYW5nL09i"
    "amVjdDs+O0xjb20vYW1hem9uYXdzL3NlcnZpY2VzL2xhbWJkYS9ydW50aW1lL0NvbnRleHQ7KUxqYXZhL2xhbmcvVm9pZDsB"
    "AFUoTGphdmEvbGFuZy9PYmplY3Q7TGNvbS9hbWF6b25hd3Mvc2VydmljZXMvbGFtYmRhL3J1bnRpbWUvQ29udGV4dDspTGph"
    "dmEvbGFuZy9PYmplY3Q7AQAQTWV0aG9kUGFyYW1ldGVycwEAj0xqYXZhL2xhbmcvT2JqZWN0O0xjb20vYW1hem9uYXdzL3Nl"
    "cnZpY2VzL2xhbWJkYS9ydW50aW1lL1JlcXVlc3RIYW5kbGVyPExqYXZhL3V0aWwvTWFwPExqYXZhL2xhbmcvU3RyaW5nO0xq"
    "YXZhL2xhbmcvT2JqZWN0Oz47TGphdmEvbGFuZy9Wb2lkOz47AQAKU291cmNlRmlsZQEAFURkYlN0cmVhbUhhbmRsZXIuamF2"
    "YQEAEEJvb3RzdHJhcE1ldGhvZHMIAX8BABNzcXMuAS5hbWF6b25hd3MuY29tCAGBAQB2Y29udGVudC10eXBlOmFwcGxpY2F0"
    "aW9uL3gtYW16LWpzb24tMS4wCmhvc3Q6AQp4LWFtei1kYXRlOgEKeC1hbXotc2VjdXJpdHktdG9rZW46AQp4LWFtei10YXJn"
    "ZXQ6QW1hem9uU1FTLlNlbmRNZXNzYWdlCggBgwEADVBPU1QKLwoKAQoBCgEIAYUBABQBLwEvc3FzL2F3czRfcmVxdWVzdAgB"
    "hwEAFkFXUzQtSE1BQy1TSEEyNTYKAQoBCgEIAYkBAAVBV1M0AQgBiwEAPUFXUzQtSE1BQy1TSEEyNTYgQ3JlZGVudGlhbD0B"
    "LwEsIFNpZ25lZEhlYWRlcnM9ASwgU2lnbmF0dXJlPQEIAY0BAApodHRwczovLwEvCAGPAQAiU2VuZE1lc3NhZ2UgZmFpbGVk"
    "IHN0YXR1cz0BIGJvZHk9AQ8GAZEKAZIBkwcBlAwAqwGVAQAkamF2YS9sYW5nL2ludm9rZS9TdHJpbmdDb25jYXRGYWN0b3J5"
    "AQCYKExqYXZhL2xhbmcvaW52b2tlL01ldGhvZEhhbmRsZXMkTG9va3VwO0xqYXZhL2xhbmcvU3RyaW5nO0xqYXZhL2xhbmcv"
    "aW52b2tlL01ldGhvZFR5cGU7TGphdmEvbGFuZy9TdHJpbmc7W0xqYXZhL2xhbmcvT2JqZWN0OylMamF2YS9sYW5nL2ludm9r"
    "ZS9DYWxsU2l0ZTsBAAxJbm5lckNsYXNzZXMBAAVFbnRyeQcBmQEAJWphdmEvbGFuZy9pbnZva2UvTWV0aG9kSGFuZGxlcyRM"
    "b29rdXAHAZsBAB5qYXZhL2xhbmcvaW52b2tlL01ldGhvZEhhbmRsZXMBAAZMb29rdXAAIQBKAAIAAQFsAAAACQABAAUABgAB"
    "AW4AAAAdAAEAAQAAAAUqtwABsQAAAAEBbwAAAAYAAQAAABYACgBNAE4AAQFuAAAAegAGAAYAAAA9uwAHWbcACUwqTSy+PgM2"
    "BBUEHaIAJSwVBDM2BSsSCgS9AAJZAxUFuAAMU7gAErYAGFeEBAGn/9srtgAcsAAAAAIBbwAAAA4AAwAAABkACAAaADgAGwFw"
    "AAAAFwAC/wAQAAUHAXEHAAcHAXEBAQAA+AAnAAoA3QDeAAIBbgAAAEAABQADAAAAIBIguAAiTSy7AChZKhIgtwAqtgAtLCuy"
    "ADG2ADe2ADuwAAAAAQFvAAAADgADAAAAHwAGACAAFAAhAXMAAAAEAAEBYQAKALIAogACAW4AAAAxAAMAAgAAABUSP7gAQUwr"
    "KrIAMbYAN7YARrgASbAAAAABAW8AAAAKAAIAAAAlAAYAJgFzAAAABAABAWEACgCKAIsAAQFuAAABGAAGAAQAAACwKhAitgBP"
    "VwM9HCu2AFKiAJorHLYAVj4dqwAAAAAAAGYAAAAFAAAACQAAAFwAAAAKAAAASAAAAA0AAABSAAAAIgAAADQAAABcAAAAPioS"
    "WrYAGFenAE8qEly2ABhXpwBFKhJetgAYV6cAOyoSYLYAGFenADEqEmK2ABhXpwAnHRAgogAbKhJkBL0AAlkDHbgAZlO4ABK2"
    "ABhXpwAJKh22AE9XhAIBp/9kKhAitgBPV7EAAAACAW8AAAA6AA4AAAAqAAcAKwARACwAFwAtAEwALgBWAC8AYAAwAGoAMQB0"
    "ADIAfgA0AJwANQCiACsAqAA4AK8AOQFwAAAAFgAK/AAJAfwAQgEJCQkJCR36AAX6AAUACgCRAJIAAQFuAAABxgACAAUAAAEH"
    "K8cADSoSa7YAGFenAPsrwQBtmQBpKhB7tgBPVwQ9K8AAbbkAbwEAuQBzAQBOLbkAeQEAmQA+LbkAfwEAwACDOgQcmgAKKhAs"
    "tgBPVwM9KhkEuQCFAQDAABO4AIgqEDq2AE9XKhkEuQCMAQC4AI+n/78qEH22AE9XpwCOK8EAk5kARyoQW7YAT1cEPSvAAJO5"
    "AJUBAE4tuQB5AQCZACEtuQB/AQA6BByaAAoqECy2AE9XAz0qGQS4AI+n/9wqEF22AE9XpwBDK8EAE5kADiorwAATuACIpwAx"
    "K8EAlpkADyortgCYtgAYV6cAHivBAJmZAA8qK7YAmLYAGFenAAsqK7YAmLgAiLEAAAACAW8AAAB6AB4AAAA9AAQAPgAOAD8A"
    "FQBAABwAQQAeAEIAQQBDAEwARABOAEUAXABGAGMARwBuAEgAcQBJAHgASgCCAEsAiQBMAIsATQCmAE4AsQBPALMAUAC5AFEA"
    "vABSAMMAUwDNAFQA2ABVAN8AVgDrAFcA8gBYAP4AWgEGAFwBcAAAAC0ADQ79AB4BBwB6/AAeBwCD+QAk+gAJ/QAZAQcAevwA"
    "GwcAAvkACvoACRESEgcACgFgAQIAAgFuAAAEMwAFACMAAAI7Epu4AJ1NEqO4AJ1OEqW4AJ06BBKnuACdOgUZBboAqQAAOga7"
    "AAdZtwAJOgcZBxB7tgBPVxkHEqy2ABhXGQcquACIGQcSrrYAGFcZByu4AIgZBxB9tgBPVxkHtgAcOggZCLgAsDoJErO4ALWy"
    "ALu2AME6ChLFuAC1sgC7tgDBOgu4AMc6DBkKGQy2AM06DRkLGQy2AM06DhkGGQ0ZBLoA0AAAOg8S0zoQGQ8ZEBkJugDVAAA6"
    "ERkOGQW6ANYAADoSGQ0ZEhkRuACwugDZAAA6Ey26ANoAALIAMbYANzoUGRQZDrgA2zoVGRUZBbgA2zoWGRYS37gA2zoXGRcS"
    "4bgA2zoYGRgZE7gA27gASToZLBkSGRAZGboA4wAAOhq7AOZZGQa6AOgAALcA6TobGRu2AOzAAPA6HBkcEvK2APQZHAS2APcZ"
    "HBL7Ev22AP8ZHBMBAxkNtgD/GRwTAQUZBLYA/xkcEwEHEwEJtgD/GRwTAQsZGrYA/xkIsgAxtgA3Oh0ZHBkdvrYBDRkctgER"
    "Oh4ZHhkdtgEVGR7GACYZHrYBG6cAHjofGR7GABQZHrYBG6cADDogGR8ZILYBIBkfvxkctgEkNh4VHhEAyKEAExUeEQEsogAL"
    "GRy2ASenAAgZHLYBKzofuwEuWbcBMDogERAAvAg6IRkfxgAeGR8ZIbYBMVk2IgKfABAZIBkhAxUitgE3p//jFR4RAMihAAsV"
    "HhEBLKEAGrsBOlkVHhkgEwE8tgE+ugFAAAC3AUO/sQACAY4BlQGiAR4BqQGuAbEBHgACAW8AAADiADgAAABgAAYAYQAMAGIA"
    "EwBjABoAZAAjAGYALABnADQAaAA8AGkAQgBqAEoAawBQAGwAWABtAF8AbgBmAHAAcwBxAIAAcgCFAHMAjgB0AJcAdgCkAHwA"
    "qAB+ALUAfwDAAIAAxgCBANAAgwDeAIQA5wCFAPAAhgD5AIcBAgCIAQ4AigEcAI0BLACOATYAjwE9AJABQwCRAUwAkgFWAJMB"
    "YACUAWsAlQF1AJYBfwCXAYcAmAGOAJkBlQCaAaIAmAG9AJsBxACcAeMAnQHsAJ4B8wCgAhMAoQIjAKICLgCjAjoApQFwAAAA"
    "7gAK/wGiAB8HABMHABMHABMHABMHABMHABMHABMHAAcHABMHABMHALYHALYHAMgHABMHABMHABMHABMHABMHABMHABMHAXEH"
    "AXEHAXEHAXEHAXEHABMHABMHAOYHAPAHAXEHARYAAQcBHv8ADgAgBwATBwATBwATBwATBwATBwATBwATBwAHBwATBwATBwC2"
    "BwC2BwDIBwATBwATBwATBwATBwATBwATBwATBwFxBwFxBwFxBwFxBwFxBwATBwATBwDmBwDwBwFxBwEWBwEeAAEHAR4I+QAC"
    "/AAeAUQHATL+ABEHATIHAS4HAXEfDxYBcwAAAAQAAQFhAAEBagFrAAIBbgAAAa8ABAALAAAA4xMBRLgAnU4rEwFGuQFIAgDA"
    "AJM6BBkEuQCVAQA6BRkFuQB5AQCZALwZBbkAfwEAOgYZBsAAbToHGQcTAUy5AUgCAMAAbToIuwAHWbcACToJGQkQe7YAT1cZ"
    "CRMBTrYAGFcZCRkHEwFQuQFIAgDAABO4AIgZCRMBUrYAGFcZCRkIEwFUuQFIAgC4AI8ZCRMBVrYAGFcZCRkIEwFYuQFIAgC4"
    "AI8ZCRMBWrYAGFcZCRkIEwFcuQFIAgC4AI8ZCRB9tgBPVy0ZCbYAHLgBXqcAEjoKuwE6WRMBYxkKtwFlv6f/QAGwAAEAwwDM"
    "AM8BYQACAW8AAABaABYAAACqAAcAqwAVAKwAMQCtADgArgBHAK8AUACwAFgAsQBhALIAcwCzAHwAtACLALUAlAC2AKMAtwCs"
    "ALgAuwC5AMMAuwDMAL4AzwC8ANEAvQDeAL8A4QDAAXAAAABSAAT+AB4HABMHAJMHAHr/ALAACgcASgcAbQcBdAcAEwcAkwcA"
    "egcAAgcAbQcAbQcABwABBwFh/wAOAAYHAEoHAG0HAXQHABMHAJMHAHoAAPoAAgF2AAAAAgF3EEEBagF4AAIBbgAAACIAAwAD"
    "AAAACiorwABtLLYBaLAAAAABAW8AAAAGAAEAAAAWAXkAAAAJAgAAEAAAABAAAAQBdgAAAAIBegF7AAAAAgF8AX0AAAA4AAkB"
    "kAABAX4BkAABAYABkAABAYIBkAABAYQBkAABAYYBkAABAYgBkAABAYoBkAABAYwBkAABAY4BlgAAABIAAgCDAG0BlwYJAZgB"
    "mgGcABk="
)


def _deployment_zip() -> bytes:
    raw = base64.b64decode(_B64)
    got = hashlib.sha256(raw).hexdigest()
    assert got == _SHA256, f"embedded class is sha256 {got!r}, pinned {_SHA256!r}"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("probe/DdbStreamHandler.class", raw)
    return buf.getvalue()


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(ctx, probe, predicate, *, timeout_s, interval_s=2.0, description="condition"):
    budgeted = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + budgeted
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not met within {budgeted:.0f}s; last saw {last!r}")


def _create_table(ctx, ddb):
    name = ctx.unique_name("sim2real-behav-javaddb-tbl-")
    ddb.create_table(
        TableName=name, BillingMode="PAY_PER_REQUEST",
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        StreamSpecification={"StreamEnabled": True, "StreamViewType": "NEW_AND_OLD_IMAGES"},
        Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=name), "ResourceNotFoundException"))
    desc = _poll_until(
        ctx, lambda: ddb.describe_table(TableName=name)["Table"],
        lambda t: t["TableStatus"] == "ACTIVE", timeout_s=120.0,
        description=f"table {name} reaching ACTIVE")
    return name, desc["LatestStreamArn"]


def _queue(ctx):
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-javaddb-q-")
    sqs.create_queue(QueueName=name, tags={"sim2real": CHECK})
    url = sqs.get_queue_url(QueueName=name)["QueueUrl"]
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    ctx.on_cleanup(_teardown(lambda: sqs.delete_queue(QueueUrl=url),
                             "AWS.SimpleQueueService.NonExistentQueue"))
    return {"name": name, "url": url, "arn": arn}


def _execution_role(ctx, *, stream_arn, queue_arn):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-javaddb-role-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole"}]}
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                          Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    inline = "sim2real-inline"
    iam.put_role_policy(RoleName=name, PolicyName=inline, PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [
            {"Effect": "Allow",
             "Action": ["dynamodb:DescribeStream", "dynamodb:GetRecords", "dynamodb:GetShardIterator",
                        "dynamodb:ListStreams"],
             "Resource": stream_arn},
            {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn},
        ]}))
    ctx.on_cleanup(_teardown(lambda: iam.delete_role_policy(RoleName=name, PolicyName=inline),
                             "NoSuchEntity"))
    return arn


def _create(ctx, lam, kwargs, timeout_s=120):
    budgeted = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + budgeted
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            propagating = (err.get("Code") == "InvalidParameterValueException"
                           and "cannot be assumed by Lambda" in err.get("Message", ""))
            if not propagating or time.monotonic() >= deadline:
                if propagating and _budget_spent(ctx):
                    raise TimeoutError(
                        "CreateFunction never succeeded: the run budget ended first; not graded"
                    ) from exc
                raise
            time.sleep(2.0)


def _wait_active(ctx, lam, fn, timeout_s=300):
    return _poll_until(
        ctx, lambda: lam.get_function_configuration(FunctionName=fn),
        lambda cfg: cfg["State"] == "Active", timeout_s=timeout_s,
        description=f"{fn} reaching State=Active")


def _function(ctx, lam, **kwargs):
    fn = kwargs["FunctionName"]
    _create(ctx, lam, kwargs)
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=fn),
                             "ResourceNotFoundException"))
    _wait_active(ctx, lam, fn)
    return fn


def _create_esm(ctx, lam, fn, stream_arn, timeout_s=90.0):
    """CreateEventSourceMapping through the role-permission propagation window; a genuine
    permission rejection, not that window, raises immediately."""
    budgeted = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + budgeted
    while True:
        try:
            created = lam.create_event_source_mapping(
                FunctionName=fn, EventSourceArn=stream_arn, StartingPosition="TRIM_HORIZON",
                BatchSize=10, Enabled=True)
            break
        except ClientError as exc:
            err = exc.response.get("Error", {})
            propagating = (err.get("Code") == "InvalidParameterValueException"
                           and "does not have permissions" in err.get("Message", ""))
            if not propagating or time.monotonic() >= deadline:
                if propagating and _budget_spent(ctx):
                    raise TimeoutError(
                        "CreateEventSourceMapping never succeeded: the run budget ended "
                        "first; not graded"
                    ) from exc
                raise
            time.sleep(2.0)
    uuid = created["UUID"]
    ctx.on_cleanup(_teardown(lambda: lam.delete_event_source_mapping(UUID=uuid),
                             "ResourceNotFoundException"))
    return uuid


def _wait_esm_enabled(ctx, lam, uuid, timeout_s=180.0):
    return _poll_until(
        ctx, lambda: lam.get_event_source_mapping(UUID=uuid),
        lambda esm: esm.get("State") == "Enabled", timeout_s=timeout_s,
        description=f"event source mapping {uuid} reaching State=Enabled")


def _drain(sqs, url) -> list:
    out = []
    while True:
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=1)
        msgs = resp.get("Messages", [])
        if not msgs:
            return out
        for m in msgs:
            out.append(json.loads(m["Body"]))
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:eventing",
      "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Java RequestHandler<Map,Void> walks a DynamoDB stream record's nested Keys, NewImage and
    OldImage through generic Maps (no DynamodbEvent POJO): INSERT carries only NewImage, MODIFY
    carries both exactly, REMOVE carries only OldImage.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/with-ddb.html
    Reference: https://docs.aws.amazon.com/lambda/latest/dg/java-handler.html
    """
    ddb = ctx.client("dynamodb")
    lam = ctx.client("lambda")

    table, stream_arn = _create_table(ctx, ddb)
    observe = _queue(ctx)
    role_arn = _execution_role(ctx, stream_arn=stream_arn, queue_arn=observe["arn"])
    fn = ctx.unique_name("sim2real-behav-javaddb-fn-")
    fn = _function(ctx, lam, FunctionName=fn, Runtime="java21",
                   Handler="probe.DdbStreamHandler", Role=role_arn,
                   Code={"ZipFile": _deployment_zip()}, MemorySize=512, Timeout=20,
                   Environment={"Variables": {"OBSERVE_QUEUE_URL": observe["url"]}},
                   Tags={"sim2real": CHECK})
    esm = _create_esm(ctx, lam, fn, stream_arn)
    _wait_esm_enabled(ctx, lam, esm)

    k = ctx.unique_name("item-")
    ddb.put_item(TableName=table, Item={"pk": {"S": k}, "n": {"N": "1"}})
    ddb.update_item(TableName=table, Key={"pk": {"S": k}}, UpdateExpression="SET n = :two",
                    ExpressionAttributeValues={":two": {"N": "2"}})
    ddb.delete_item(TableName=table, Key={"pk": {"S": k}})

    sqs = ctx.client("sqs")

    def _mine():
        return [r for r in _drain(sqs, observe["url"])
                if (r.get("keys") or {}).get("pk", {}).get("S") == k]

    # Delivery is at-least-once, so a record can arrive twice; wait for each event name.
    seen: dict = {}

    def _probe():
        for r in _mine():
            seen.setdefault(r["eventName"], r)
        return seen

    by_name = _poll_until(ctx, _probe, lambda rs: {"INSERT", "MODIFY", "REMOVE"} <= set(rs),
                          timeout_s=180.0, interval_s=2.0,
                          description="INSERT, MODIFY and REMOVE stream records for the item "
                                      "reaching the handler")
    assert set(by_name) == {"INSERT", "MODIFY", "REMOVE"}, (
        f"saw event names {sorted(by_name)}, expected all three")

    insert = by_name["INSERT"]
    assert insert.get("newImage") == {"pk": {"S": k}, "n": {"N": "1"}}, insert
    assert not insert.get("oldImage"), f"INSERT must carry no OldImage: {insert}"

    modify = by_name["MODIFY"]
    assert modify.get("oldImage") == {"pk": {"S": k}, "n": {"N": "1"}}, modify
    assert modify.get("newImage") == {"pk": {"S": k}, "n": {"N": "2"}}, modify

    remove = by_name["REMOVE"]
    assert remove.get("oldImage") == {"pk": {"S": k}, "n": {"N": "2"}}, remove
    assert not remove.get("newImage"), f"REMOVE must carry no NewImage: {remove}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
