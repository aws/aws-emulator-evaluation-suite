"""java21-snapstart-crac-hooks-and-restore-accounting."""

from __future__ import annotations

import base64
import concurrent.futures
import hashlib
import io
import json
import re
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "java21-snapstart-crac-hooks-and-restore-accounting"
GROUP = 'state-machine'
SERVICES = ['lambda']

# Each invocation holds its execution environment open this long, so a burst of BURST calls is
# forced into BURST DISTINCT restored environments instead of one warm reuse.
HOLD_MS = 6000
BURST = 3

# The Java 21 managed runtime does NOT provide org.crac (a package without it dies with
# `java.lang.NoClassDefFoundError: org/crac/Resource` at class load), so the package ships a minimal
# org.crac API of its own, CRAC_API_SOURCE. It does NOT shadow the runtime's own implementation: the
# handler reports the resolved global context as `org.crac.GlobalContextWrapper`, which delegates
# to the platform's checkpoint coordinator, and the hooks fire.
#
# The bytecode (javac --release 21 -g:none) is embedded as base64 with its SHA-256 asserted, so the
# check needs no JDK; the Java sources are reproduced in JAVA_SOURCE and CRAC_API_SOURCE.
JAVA_SOURCE = r'''
package probe;
public class SnapHandler implements RequestHandler<In, Map<String, Object>> {
    static final String INIT_ID = UUID.randomUUID().toString();
    static final Random SEEDED = new Random(12345L);
    static final int FIRST_DRAW = SEEDED.nextInt(1000000);
    static final SecureRandom SECURE = new SecureRandom();
    static volatile String restoreId = "no-restore-hook-ran";
    static volatile int beforeCheckpointCount = 0;
    static volatile int afterRestoreCount = 0;
    static volatile String hookRegistration = "not-attempted";
    static final Resource HOOK = new Resource() {
        public void beforeCheckpoint(org.crac.Context<? extends Resource> c) {
            beforeCheckpointCount++;
        }
        public void afterRestore(org.crac.Context<? extends Resource> c) {
            afterRestoreCount++;
            restoreId = UUID.randomUUID().toString();
        }
    };
    static {
        try {
            Core.getGlobalContext().register(HOOK);
            hookRegistration = "ok:" + Core.getGlobalContext().getClass().getName();
        } catch (Throwable t) { hookRegistration = "failed:" + t.getClass().getName(); }
    }
    public Map<String, Object> handleRequest(In in, Context ctx) {
        // holds the sandbox, then reports: INIT_ID and FIRST_DRAW are pre-snapshot state;
        // SEEDED.nextInt() is drawn POST-restore off the restored PRNG; SECURE/UUID per invoke.
    }
}
'''

CRAC_API_SOURCE = r'''
package org.crac;

public interface Resource {
    void beforeCheckpoint(Context<? extends Resource> context) throws Exception;

    void afterRestore(Context<? extends Resource> context) throws Exception;
}

package org.crac;

public abstract class Context<R extends Resource> implements Resource {
    protected Context() {}

    public abstract void register(R resource);
}

package org.crac;

public final class Core {
    private static final Context<Resource> GLOBAL = load();

    private Core() {}

    public static Context<Resource> getGlobalContext() {
        if (GLOBAL == null) {
            throw new UnsupportedOperationException("this JVM provides no CRaC implementation");
        }
        return GLOBAL;
    }

    private static Context<Resource> load() {
        String named = System.getProperty("org.crac.Core.Compat");
        String[] candidates = named != null
                ? new String[] {named, "javax.crac", "jdk.crac"}
                : new String[] {"javax.crac", "jdk.crac"};
        for (String pkg : candidates) {
            try {
                return new GlobalContextWrapper(pkg);
            } catch (ReflectiveOperationException | LinkageError e) {
                // try the next implementation
            }
        }
        return null;
    }
}

package org.crac;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;

final class GlobalContextWrapper extends Context<Resource> {
    private final Object platform;
    private final Class<?> resourceType;
    private final Method register;
    private final List<Object> held = new ArrayList<>();

    GlobalContextWrapper(String pkg) throws ReflectiveOperationException {
        ClassLoader loader = GlobalContextWrapper.class.getClassLoader();
        resourceType = Class.forName(pkg + ".Resource", false, loader);
        Class<?> contextType = Class.forName(pkg + ".Context", false, loader);
        platform = Class.forName(pkg + ".Core", true, loader).getMethod("getGlobalContext").invoke(null);
        register = contextType.getMethod("register", resourceType);
    }

    @Override
    public void beforeCheckpoint(Context<? extends Resource> context) {
        throw new UnsupportedOperationException("the platform calls its own context");
    }

    @Override
    public void afterRestore(Context<? extends Resource> context) {
        throw new UnsupportedOperationException("the platform calls its own context");
    }

    @Override
    public synchronized void register(Resource resource) {
        Object proxy = Proxy.newProxyInstance(
                GlobalContextWrapper.class.getClassLoader(),
                new Class<?>[] {resourceType},
                (self, method, args) -> {
                    switch (method.getName()) {
                        case "beforeCheckpoint":
                            resource.beforeCheckpoint(this);
                            return null;
                        case "afterRestore":
                            resource.afterRestore(this);
                            return null;
                        case "hashCode":
                            return System.identityHashCode(self);
                        case "equals":
                            return self == args[0];
                        case "toString":
                            return "org.crac proxy for " + resource;
                        default:
                            throw new UnsupportedOperationException(method.getName());
                    }
                });
        held.add(resource);
        held.add(proxy);
        try {
            register.invoke(platform, proxy);
        } catch (InvocationTargetException e) {
            throw new IllegalStateException(e.getCause());
        } catch (IllegalAccessException e) {
            throw new IllegalStateException(e);
        }
    }
}
'''

_SHA256 = {
    "probe/In.class": "17d036d34668afa414fec627b2a051e1c73a4d3b1309fee8dfac24290659e56a",
    "probe/SnapHandler.class": "358b83a9d4f8329d83366ba4d157bc7acc171fb2be25a9bcf59dd3980406d95d",
    "probe/SnapHandler$1.class": "3bcf8b16898e0eeef1911d8c677d12335ed1a13f3c237eb3b7703d91381b4012",
    "org/crac/Resource.class": "8aba1b195ecaa2afdaf97b3fe27064ff8173127840560918153648699e5ad2d2",
    "org/crac/Context.class": "5390562fdee74bf1576a4c07946bf0858044da648368d3c4a63d9738999186bf",
    "org/crac/Core.class": "b8d8115208be67af41b5097a59d9ea80a352332dc0381a723c49a16953b1bfec",
    "org/crac/GlobalContextWrapper.class": "116625752ed7f855383f20eb19a461d94ccf10bd92e1d8dbb9a7c12e5d1858b0",
}

_B64 = {  # @@GENERATED@@ probe/In.class probe/SnapHandler.class probe/SnapHandler$1.class org/crac/Resource.class org/crac/Context.class org/crac/Core.class org/crac/GlobalContextWrapper.class
    "probe/In.class":
        "yv66vgAAAEEAGQoAAgADBwAEDAAFAAYBABBqYXZhL2xhbmcvT2JqZWN0AQAGPGluaXQ+AQADKClWBwAIAQAIcHJvYmUvSW4B"
        "AARtb2RlAQASTGphdmEvbGFuZy9TdHJpbmc7AQABbgEAAUkBAAVpdGVtcwEAEExqYXZhL3V0aWwvTGlzdDsBAAlTaWduYXR1"
        "cmUBACRMamF2YS91dGlsL0xpc3Q8TGphdmEvbGFuZy9TdHJpbmc7PjsBAAZob2xkTXMBAARDb2RlAQAPTGluZU51bWJlclRh"
        "YmxlAQASTG9jYWxWYXJpYWJsZVRhYmxlAQAEdGhpcwEACkxwcm9iZS9JbjsBAApTb3VyY2VGaWxlAQAHSW4uamF2YQAhAAcA"
        "AgAAAAQAAQAJAAoAAAABAAsADAAAAAEADQAOAAEADwAAAAIAEAABABEADAAAAAEAAQAFAAYAAQASAAAALwABAAEAAAAFKrcA"
        "AbEAAAACABMAAAAGAAEAAAAEABQAAAAMAAEAAAAFABUAFgAAAAEAFwAAAAIAGA==",
    "probe/SnapHandler.class":
        "yv66vgAAAEEBAwoAAgADBwAEDAAFAAYBABBqYXZhL2xhbmcvT2JqZWN0AQAGPGluaXQ+AQADKClWCQAIAAkHAAoMAAsADAEA"
        "CHByb2JlL0luAQAGaG9sZE1zAQABSQoADgAPBwAQDAARABIBABBqYXZhL2xhbmcvVGhyZWFkAQAFc2xlZXABAAQoSilWBwAU"
        "AQAeamF2YS9sYW5nL0ludGVycnVwdGVkRXhjZXB0aW9uCQAWABcHABgMABkAGgEAEXByb2JlL1NuYXBIYW5kbGVyAQAGU0VD"
        "VVJFAQAcTGphdmEvc2VjdXJpdHkvU2VjdXJlUmFuZG9tOwoAHAAdBwAeDAAfACABABpqYXZhL3NlY3VyaXR5L1NlY3VyZVJh"
        "bmRvbQEACW5leHRCeXRlcwEABShbQilWBwAiAQAXamF2YS9sYW5nL1N0cmluZ0J1aWxkZXIKACEAAwgAJQEABCUwMngKACcA"
        "KAcAKQwAKgArAQAOamF2YS9sYW5nL0J5dGUBAAd2YWx1ZU9mAQATKEIpTGphdmEvbGFuZy9CeXRlOwoALQAuBwAvDAAwADEB"
        "ABBqYXZhL2xhbmcvU3RyaW5nAQAGZm9ybWF0AQA5KExqYXZhL2xhbmcvU3RyaW5nO1tMamF2YS9sYW5nL09iamVjdDspTGph"
        "dmEvbGFuZy9TdHJpbmc7CgAhADMMADQANQEABmFwcGVuZAEALShMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9TdHJp"
        "bmdCdWlsZGVyOwcANwEAF2phdmEvdXRpbC9MaW5rZWRIYXNoTWFwCgA2AAMIADoBAAZpbml0SWQJABYAPAwAPQA+AQAHSU5J"
        "VF9JRAEAEkxqYXZhL2xhbmcvU3RyaW5nOwsAQABBBwBCDABDAEQBAA1qYXZhL3V0aWwvTWFwAQADcHV0AQA4KExqYXZhL2xh"
        "bmcvT2JqZWN0O0xqYXZhL2xhbmcvT2JqZWN0OylMamF2YS9sYW5nL09iamVjdDsIAEYBAAlyZXN0b3JlSWQJABYASAwARgA+"
        "CABKAQAQaG9va1JlZ2lzdHJhdGlvbgkAFgBMDABKAD4IAE4BABViZWZvcmVDaGVja3BvaW50Q291bnQJABYAUAwATgAMCgBS"
        "AFMHAFQMACoAVQEAEWphdmEvbGFuZy9JbnRlZ2VyAQAWKEkpTGphdmEvbGFuZy9JbnRlZ2VyOwgAVwEAEWFmdGVyUmVzdG9y"
        "ZUNvdW50CQAWAFkMAFcADAgAWwEACWZpcnN0RHJhdwkAFgBdDABeAAwBAApGSVJTVF9EUkFXCABgAQAIbmV4dERyYXcJABYA"
        "YgwAYwBkAQAGU0VFREVEAQASTGphdmEvdXRpbC9SYW5kb207AwAPQkAKAGcAaAcAaQwAagBrAQAQamF2YS91dGlsL1JhbmRv"
        "bQEAB25leHRJbnQBAAQoSSlJCABtAQAPc2VjdXJlUmFuZG9tSGV4CgAhAG8MAHAAcQEACHRvU3RyaW5nAQAUKClMamF2YS9s"
        "YW5nL1N0cmluZzsIAHMBAAR1dWlkCgB1AHYHAHcMAHgAeQEADmphdmEvdXRpbC9VVUlEAQAKcmFuZG9tVVVJRAEAEigpTGph"
        "dmEvdXRpbC9VVUlEOwoAdQBvCAB8AQALamF2YVZlcnNpb24IAH4BAAxqYXZhLnZlcnNpb24KAIAAgQcAggwAgwCEAQAQamF2"
        "YS9sYW5nL1N5c3RlbQEAC2dldFByb3BlcnR5AQAmKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1N0cmluZzsIAIYB"
        "AAZ2bU5hbWUIAIgBAAxqYXZhLnZtLm5hbWUIAIoBAAlsb2dTdHJlYW0LAIwAjQcAjgwAjwBxAQAtY29tL2FtYXpvbmF3cy9z"
        "ZXJ2aWNlcy9sYW1iZGEvcnVudGltZS9Db250ZXh0AQAQZ2V0TG9nU3RyZWFtTmFtZQgAkQEADGVudkxvZ1N0cmVhbQgAkwEA"
        "GkFXU19MQU1CREFfTE9HX1NUUkVBTV9OQU1FCgCAAJUMAJYAhAEABmdldGVudggAmAEADGF3c1JlcXVlc3RJZAsAjACaDACb"
        "AHEBAA9nZXRBd3NSZXF1ZXN0SWQKABYAnQwAngCfAQANaGFuZGxlUmVxdWVzdAEASihMcHJvYmUvSW47TGNvbS9hbWF6b25h"
        "d3Mvc2VydmljZXMvbGFtYmRhL3J1bnRpbWUvQ29udGV4dDspTGphdmEvdXRpbC9NYXA7BQAAAAAAADA5CgBnAKMMAAUAEgoA"
        "HAADCACmAQATbm8tcmVzdG9yZS1ob29rLXJhbggAqAEADW5vdC1hdHRlbXB0ZWQHAKoBABNwcm9iZS9TbmFwSGFuZGxlciQx"
        "CgCpAAMJABYArQwArgCvAQAESE9PSwEAE0xvcmcvY3JhYy9SZXNvdXJjZTsKALEAsgcAswwAtAC1AQANb3JnL2NyYWMvQ29y"
        "ZQEAEGdldEdsb2JhbENvbnRleHQBABQoKUxvcmcvY3JhYy9Db250ZXh0OwoAtwC4BwC5DAC6ALsBABBvcmcvY3JhYy9Db250"
        "ZXh0AQAIcmVnaXN0ZXIBABYoTG9yZy9jcmFjL1Jlc291cmNlOylWCgACAL0MAL4AvwEACGdldENsYXNzAQATKClMamF2YS9s"
        "YW5nL0NsYXNzOwoAwQDCBwDDDADEAHEBAA9qYXZhL2xhbmcvQ2xhc3MBAAdnZXROYW1lEgAAAMYMAMcAhAEAF21ha2VDb25j"
        "YXRXaXRoQ29uc3RhbnRzBwDJAQATamF2YS9sYW5nL1Rocm93YWJsZQoAyADLDADMAHEBAApnZXRNZXNzYWdlEgABAM4MAMcA"
        "zwEAOChMamF2YS9sYW5nL1N0cmluZztMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9TdHJpbmc7BwDRAQA0Y29tL2Ft"
        "YXpvbmF3cy9zZXJ2aWNlcy9sYW1iZGEvcnVudGltZS9SZXF1ZXN0SGFuZGxlcgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUB"
        "ABJMb2NhbFZhcmlhYmxlVGFibGUBAAR0aGlzAQATTHByb2JlL1NuYXBIYW5kbGVyOwEAAXgBAAFCAQACaW4BAApMcHJvYmUv"
        "SW47AQADY3R4AQAvTGNvbS9hbWF6b25hd3Mvc2VydmljZXMvbGFtYmRhL3J1bnRpbWUvQ29udGV4dDsBAAFiAQACW0IBAANo"
        "ZXgBABlMamF2YS9sYW5nL1N0cmluZ0J1aWxkZXI7AQADb3V0AQAPTGphdmEvdXRpbC9NYXA7AQAWTG9jYWxWYXJpYWJsZVR5"
        "cGVUYWJsZQEANUxqYXZhL3V0aWwvTWFwPExqYXZhL2xhbmcvU3RyaW5nO0xqYXZhL2xhbmcvT2JqZWN0Oz47AQANU3RhY2tN"
        "YXBUYWJsZQcA3gEACVNpZ25hdHVyZQEAcChMcHJvYmUvSW47TGNvbS9hbWF6b25hd3Mvc2VydmljZXMvbGFtYmRhL3J1bnRp"
        "bWUvQ29udGV4dDspTGphdmEvdXRpbC9NYXA8TGphdmEvbGFuZy9TdHJpbmc7TGphdmEvbGFuZy9PYmplY3Q7PjsBAFUoTGph"
        "dmEvbGFuZy9PYmplY3Q7TGNvbS9hbWF6b25hd3Mvc2VydmljZXMvbGFtYmRhL3J1bnRpbWUvQ29udGV4dDspTGphdmEvbGFu"
        "Zy9PYmplY3Q7AQAQTWV0aG9kUGFyYW1ldGVycwEACDxjbGluaXQ+AQABdAEAFUxqYXZhL2xhbmcvVGhyb3dhYmxlOwEAiUxq"
        "YXZhL2xhbmcvT2JqZWN0O0xjb20vYW1hem9uYXdzL3NlcnZpY2VzL2xhbWJkYS9ydW50aW1lL1JlcXVlc3RIYW5kbGVyPExw"
        "cm9iZS9JbjtMamF2YS91dGlsL01hcDxMamF2YS9sYW5nL1N0cmluZztMamF2YS9sYW5nL09iamVjdDs+Oz47AQAKU291cmNl"
        "RmlsZQEAEFNuYXBIYW5kbGVyLmphdmEBAAtOZXN0TWVtYmVycwEAEEJvb3RzdHJhcE1ldGhvZHMIAPQBAARvazoBCAD2AQAK"
        "ZmFpbGVkOgE6AQ8GAPgKAPkA+gcA+wwAxwD8AQAkamF2YS9sYW5nL2ludm9rZS9TdHJpbmdDb25jYXRGYWN0b3J5AQCYKExq"
        "YXZhL2xhbmcvaW52b2tlL01ldGhvZEhhbmRsZXMkTG9va3VwO0xqYXZhL2xhbmcvU3RyaW5nO0xqYXZhL2xhbmcvaW52b2tl"
        "L01ldGhvZFR5cGU7TGphdmEvbGFuZy9TdHJpbmc7W0xqYXZhL2xhbmcvT2JqZWN0OylMamF2YS9sYW5nL2ludm9rZS9DYWxs"
        "U2l0ZTsBAAxJbm5lckNsYXNzZXMHAP8BACVqYXZhL2xhbmcvaW52b2tlL01ldGhvZEhhbmRsZXMkTG9va3VwBwEBAQAeamF2"
        "YS9sYW5nL2ludm9rZS9NZXRob2RIYW5kbGVzAQAGTG9va3VwACEAFgACAAEA0AAJABgAPQA+AAAAGABjAGQAAAAYAF4ADAAA"
        "ABgAGQAaAAAASABGAD4AAABIAE4ADAAAAEgAVwAMAAAASABKAD4AAAAYAK4ArwAAAAQAAQAFAAYAAQDSAAAALwABAAEAAAAF"
        "KrcAAbEAAAACANMAAAAGAAEAAAASANQAAAAMAAEAAAAFANUA1gAAAAEAngCfAAIA0gAAAkUABgAJAAABRivGABYrtAAHngAP"
        "K7QAB4W4AA2nAAROEBC8CE6yABUttgAbuwAhWbcAIzoELToFGQW+NgYDNgcVBxUGogAnGQUVBzM2CBkEEiQEvQACWQMVCLgA"
        "JlO4ACy2ADJXhAcBp//YuwA2WbcAODoFGQUSObIAO7kAPwMAVxkFEkWyAEe5AD8DAFcZBRJJsgBLuQA/AwBXGQUSTbIAT7gA"
        "UbkAPwMAVxkFElayAFi4AFG5AD8DAFcZBRJasgBcuABRuQA/AwBXGQUSX7IAYRJltgBmuABRuQA/AwBXGQUSbBkEtgBuuQA/"
        "AwBXGQUScrgAdLYAerkAPwMAVxkFEnsSfbgAf7kAPwMAVxkFEoUSh7gAf7kAPwMAVxkFEoksuQCLAQC5AD8DAFcZBRKQEpK4"
        "AJS5AD8DAFcZBRKXLLkAmQEAuQA/AwBXGQWwAAEACwATABYAEwAEANMAAABaABYAAAAyAAsAMwAXADUAHAA2ACMANwAsADgA"
        "YgA6AGsAOwB4ADwAhQA9AJIAPgCiAD8AsgBAAMIAQQDXAEIA5gBDAPYARAEFAEUBFABGASQARwEzAEgBQwBJANQAAABIAAcA"
        "RQAXANcA2AAIAAABRgDVANYAAAAAAUYA2QDaAAEAAAFGANsA3AACABwBKgDdAN4AAwAsARoA3wDgAAQAawDbAOEA4gAFAOMA"
        "AAAMAAEAawDbAOEA5AAFAOUAAAAlAARWBwATAP8AHwAIBwAWBwAIBwCMBwDmBwAhBwDmAQEAAPgAKgDnAAAAAgDoEEEAngDp"
        "AAIA0gAAADQAAwADAAAACiorwAAILLYAnLAAAAACANMAAAAGAAEAAAASANQAAAAMAAEAAAAKANUA1gAAAOoAAAAJAgAAEAAA"
        "ABAAAAgA6wAGAAEA0gAAAPIABAABAAAAebgAdLYAerMAO7sAZ1kUAKC3AKKzAGGyAGESZbYAZrMAXLsAHFm3AKSzABUSpbMA"
        "RwOzAE8DswBYEqezAEu7AKlZtwCrswCsuACwsgCstgC2uACwtgC8tgDAugDFAACzAEunABdLKrYAvLYAwCq2AMq6AM0AALMA"
        "S7EAAQBHAGEAZADIAAMA0wAAAD4ADwAAABQACQAVABYAFgAhABcAKwAZADAAGgA0ABsAOAAcAD0AHgBHACoAUAArAGEALgBk"
        "ACwAZQAtAHgALwDUAAAADAABAGUAEwDsAO0AAADlAAAACQAC9wBkBwDIEwAFAOcAAAACAO4A7wAAAAIA8ADxAAAABAABAKkA"
        "8gAAAA4AAgD3AAEA8wD3AAEA9QD9AAAAEgACAKkAAAAAAAAA/gEAAQIAGQ==",
    "probe/SnapHandler$1.class":
        "yv66vgAAAEEANQoAAgADBwAEDAAFAAYBABBqYXZhL2xhbmcvT2JqZWN0AQAGPGluaXQ+AQADKClWCQAIAAkHAAoMAAsADAEA"
        "EXByb2JlL1NuYXBIYW5kbGVyAQAVYmVmb3JlQ2hlY2twb2ludENvdW50AQABSQkACAAODAAPAAwBABFhZnRlclJlc3RvcmVD"
        "b3VudAoAEQASBwATDAAUABUBAA5qYXZhL3V0aWwvVVVJRAEACnJhbmRvbVVVSUQBABIoKUxqYXZhL3V0aWwvVVVJRDsKABEA"
        "FwwAGAAZAQAIdG9TdHJpbmcBABQoKUxqYXZhL2xhbmcvU3RyaW5nOwkACAAbDAAcAB0BAAlyZXN0b3JlSWQBABJMamF2YS9s"
        "YW5nL1N0cmluZzsHAB8BABNwcm9iZS9TbmFwSGFuZGxlciQxBwAhAQARb3JnL2NyYWMvUmVzb3VyY2UBAARDb2RlAQAPTGlu"
        "ZU51bWJlclRhYmxlAQASTG9jYWxWYXJpYWJsZVRhYmxlAQAEdGhpcwEAFUxwcm9iZS9TbmFwSGFuZGxlciQxOwEAEGJlZm9y"
        "ZUNoZWNrcG9pbnQBABUoTG9yZy9jcmFjL0NvbnRleHQ7KVYBAAFjAQASTG9yZy9jcmFjL0NvbnRleHQ7AQAWTG9jYWxWYXJp"
        "YWJsZVR5cGVUYWJsZQEAKExvcmcvY3JhYy9Db250ZXh0PCtMb3JnL2NyYWMvUmVzb3VyY2U7PjsBAAlTaWduYXR1cmUBACso"
        "TG9yZy9jcmFjL0NvbnRleHQ8K0xvcmcvY3JhYy9SZXNvdXJjZTs+OylWAQAMYWZ0ZXJSZXN0b3JlAQAKU291cmNlRmlsZQEA"
        "EFNuYXBIYW5kbGVyLmphdmEBAA9FbmNsb3NpbmdNZXRob2QBAAhOZXN0SG9zdAEADElubmVyQ2xhc3NlcwAgAB4AAgABACAA"
        "AAADAAAABQAGAAEAIgAAAC8AAQABAAAABSq3AAGxAAAAAgAjAAAABgABAAAAHgAkAAAADAABAAAABQAlACYAAAABACcAKAAC"
        "ACIAAABTAAIAAgAAAAmyAAcEYLMAB7EAAAADACMAAAAKAAIAAAAgAAgAIQAkAAAAFgACAAAACQAlACYAAAAAAAkAKQAqAAEA"
        "KwAAAAwAAQAAAAkAKQAsAAEALQAAAAIALgABAC8AKAACACIAAABgAAIAAgAAABKyAA0EYLMADbgAELYAFrMAGrEAAAADACMA"
        "AAAOAAMAAAAjAAgAJAARACUAJAAAABYAAgAAABIAJQAmAAAAAAASACkAKgABACsAAAAMAAEAAAASACkALAABAC0AAAACAC4A"
        "BAAwAAAAAgAxADIAAAAEAAgAAAAzAAAAAgAIADQAAAAKAAEAHgAAAAAAAA==",
    "org/crac/Resource.class":
        "yv66vgAAAEEADQcAAgEAEW9yZy9jcmFjL1Jlc291cmNlBwAEAQAQamF2YS9sYW5nL09iamVjdAEAEGJlZm9yZUNoZWNrcG9p"
        "bnQBABUoTG9yZy9jcmFjL0NvbnRleHQ7KVYBAApFeGNlcHRpb25zBwAJAQATamF2YS9sYW5nL0V4Y2VwdGlvbgEACVNpZ25h"
        "dHVyZQEAKyhMb3JnL2NyYWMvQ29udGV4dDwrTG9yZy9jcmFjL1Jlc291cmNlOz47KVYBAAxhZnRlclJlc3RvcmUGAQABAAMA"
        "AAAAAAIEAQAFAAYAAgAHAAAABAABAAgACgAAAAIACwQBAAwABgACAAcAAAAEAAEACAAKAAAAAgALAAA=",
    "org/crac/Context.class":
        "yv66vgAAAEEAEQoAAgADBwAEDAAFAAYBABBqYXZhL2xhbmcvT2JqZWN0AQAGPGluaXQ+AQADKClWBwAIAQAQb3JnL2NyYWMv"
        "Q29udGV4dAcACgEAEW9yZy9jcmFjL1Jlc291cmNlAQAEQ29kZQEACHJlZ2lzdGVyAQAWKExvcmcvY3JhYy9SZXNvdXJjZTsp"
        "VgEACVNpZ25hdHVyZQEABihUUjspVgEAPTxSOjpMb3JnL2NyYWMvUmVzb3VyY2U7PkxqYXZhL2xhbmcvT2JqZWN0O0xvcmcv"
        "Y3JhYy9SZXNvdXJjZTsEIQAHAAIAAQAJAAAAAgAEAAUABgABAAsAAAARAAEAAQAAAAUqtwABsQAAAAAEAQAMAA0AAQAOAAAA"
        "AgAPAAEADgAAAAIAEA==",
    "org/crac/Core.class":
        "yv66vgAAAEEAOAoAAgADBwAEDAAFAAYBABBqYXZhL2xhbmcvT2JqZWN0AQAGPGluaXQ+AQADKClWCQAIAAkHAAoMAAsADAEA"
        "DW9yZy9jcmFjL0NvcmUBAAZHTE9CQUwBABJMb3JnL2NyYWMvQ29udGV4dDsHAA4BACdqYXZhL2xhbmcvVW5zdXBwb3J0ZWRP"
        "cGVyYXRpb25FeGNlcHRpb24IABABACh0aGlzIEpWTSBwcm92aWRlcyBubyBDUmFDIGltcGxlbWVudGF0aW9uCgANABIMAAUA"
        "EwEAFShMamF2YS9sYW5nL1N0cmluZzspVggAFQEAFG9yZy5jcmFjLkNvcmUuQ29tcGF0CgAXABgHABkMABoAGwEAEGphdmEv"
        "bGFuZy9TeXN0ZW0BAAtnZXRQcm9wZXJ0eQEAJihMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9TdHJpbmc7BwAdAQAQ"
        "amF2YS9sYW5nL1N0cmluZwgAHwEACmphdmF4LmNyYWMIACEBAAhqZGsuY3JhYwcAIwEAHW9yZy9jcmFjL0dsb2JhbENvbnRl"
        "eHRXcmFwcGVyCgAiABIHACYBACZqYXZhL2xhbmcvUmVmbGVjdGl2ZU9wZXJhdGlvbkV4Y2VwdGlvbgcAKAEAFmphdmEvbGFu"
        "Zy9MaW5rYWdlRXJyb3IKAAgAKgwAKwAsAQAEbG9hZAEAFCgpTG9yZy9jcmFjL0NvbnRleHQ7AQAJU2lnbmF0dXJlAQAnTG9y"
        "Zy9jcmFjL0NvbnRleHQ8TG9yZy9jcmFjL1Jlc291cmNlOz47AQAEQ29kZQEAEGdldEdsb2JhbENvbnRleHQBAA1TdGFja01h"
        "cFRhYmxlAQApKClMb3JnL2NyYWMvQ29udGV4dDxMb3JnL2NyYWMvUmVzb3VyY2U7PjsHADQBABNbTGphdmEvbGFuZy9TdHJp"
        "bmc7BwA2AQATamF2YS9sYW5nL1Rocm93YWJsZQEACDxjbGluaXQ+ADEACAACAAAAAQAaAAsADAABAC0AAAACAC4ABAACAAUA"
        "BgABAC8AAAARAAEAAQAAAAUqtwABsQAAAAAACQAwACwAAgAvAAAAKQADAAAAAAAUsgAHxwANuwANWRIPtwARv7IAB7AAAAAB"
        "ADEAAAADAAEQAC0AAAACADIACgArACwAAgAvAAAAuwAEAAcAAABWEhS4ABZLKsYAGAa9ABxZAypTWQQSHlNZBRIgU6cAEQW9"
        "ABxZAxIeU1kEEiBTTCtNLL4+AzYEFQQdogAbLBUEMjoFuwAiWRkFtwAksDoGhAQBp//lAbAAAgBCAEsATAAlAEIASwBMACcA"
        "AQAxAAAAQwAF/AAfBwAcTQcAM/8ACAAFBwAcBwAzBwAzAQEAAP8AFQAGBwAcBwAzBwAzAQEHABwAAQcANf8ABwACBwAcBwAz"
        "AAAALQAAAAIAMgAIADcABgABAC8AAAATAAEAAAAAAAe4ACmzAAexAAAAAAAA",
    "org/crac/GlobalContextWrapper.class":
        "yv66vgAAAEEAvwoAAgADBwAEDAAFAAYBABBvcmcvY3JhYy9Db250ZXh0AQAGPGluaXQ+AQADKClWBwAIAQATamF2YS91dGls"
        "L0FycmF5TGlzdAoABwADCQALAAwHAA0MAA4ADwEAHW9yZy9jcmFjL0dsb2JhbENvbnRleHRXcmFwcGVyAQAEaGVsZAEAEExq"
        "YXZhL3V0aWwvTGlzdDsKABEAEgcAEwwAFAAVAQAPamF2YS9sYW5nL0NsYXNzAQAOZ2V0Q2xhc3NMb2FkZXIBABkoKUxqYXZh"
        "L2xhbmcvQ2xhc3NMb2FkZXI7EgAAABcMABgAGQEAF21ha2VDb25jYXRXaXRoQ29uc3RhbnRzAQAmKExqYXZhL2xhbmcvU3Ry"
        "aW5nOylMamF2YS9sYW5nL1N0cmluZzsKABEAGwwAHAAdAQAHZm9yTmFtZQEAPShMamF2YS9sYW5nL1N0cmluZztaTGphdmEv"
        "bGFuZy9DbGFzc0xvYWRlcjspTGphdmEvbGFuZy9DbGFzczsJAAsAHwwAIAAhAQAMcmVzb3VyY2VUeXBlAQARTGphdmEvbGFu"
        "Zy9DbGFzczsSAAEAFxIAAgAXCAAlAQAQZ2V0R2xvYmFsQ29udGV4dAoAEQAnDAAoACkBAAlnZXRNZXRob2QBAEAoTGphdmEv"
        "bGFuZy9TdHJpbmc7W0xqYXZhL2xhbmcvQ2xhc3M7KUxqYXZhL2xhbmcvcmVmbGVjdC9NZXRob2Q7BwArAQAQamF2YS9sYW5n"
        "L09iamVjdAoALQAuBwAvDAAwADEBABhqYXZhL2xhbmcvcmVmbGVjdC9NZXRob2QBAAZpbnZva2UBADkoTGphdmEvbGFuZy9P"
        "YmplY3Q7W0xqYXZhL2xhbmcvT2JqZWN0OylMamF2YS9sYW5nL09iamVjdDsJAAsAMwwANAA1AQAIcGxhdGZvcm0BABJMamF2"
        "YS9sYW5nL09iamVjdDsIADcBAAhyZWdpc3RlcgkACwA5DAA3ADoBABpMamF2YS9sYW5nL3JlZmxlY3QvTWV0aG9kOwcAPAEA"
        "J2phdmEvbGFuZy9VbnN1cHBvcnRlZE9wZXJhdGlvbkV4Y2VwdGlvbggAPgEAInRoZSBwbGF0Zm9ybSBjYWxscyBpdHMgb3du"
        "IGNvbnRleHQKADsAQAwABQBBAQAVKExqYXZhL2xhbmcvU3RyaW5nOylWEgADAEMMADAARAEAWShMb3JnL2NyYWMvR2xvYmFs"
        "Q29udGV4dFdyYXBwZXI7TG9yZy9jcmFjL1Jlc291cmNlOylMamF2YS9sYW5nL3JlZmxlY3QvSW52b2NhdGlvbkhhbmRsZXI7"
        "CgBGAEcHAEgMAEkASgEAF2phdmEvbGFuZy9yZWZsZWN0L1Byb3h5AQAQbmV3UHJveHlJbnN0YW5jZQEAYihMamF2YS9sYW5n"
        "L0NsYXNzTG9hZGVyO1tMamF2YS9sYW5nL0NsYXNzO0xqYXZhL2xhbmcvcmVmbGVjdC9JbnZvY2F0aW9uSGFuZGxlcjspTGph"
        "dmEvbGFuZy9PYmplY3Q7CwBMAE0HAE4MAE8AUAEADmphdmEvdXRpbC9MaXN0AQADYWRkAQAVKExqYXZhL2xhbmcvT2JqZWN0"
        "OylaBwBSAQAramF2YS9sYW5nL3JlZmxlY3QvSW52b2NhdGlvblRhcmdldEV4Y2VwdGlvbgcAVAEAH2phdmEvbGFuZy9JbGxl"
        "Z2FsU3RhdGVFeGNlcHRpb24KAFEAVgwAVwBYAQAIZ2V0Q2F1c2UBABcoKUxqYXZhL2xhbmcvVGhyb3dhYmxlOwoAUwBaDAAF"
        "AFsBABgoTGphdmEvbGFuZy9UaHJvd2FibGU7KVYHAF0BACBqYXZhL2xhbmcvSWxsZWdhbEFjY2Vzc0V4Y2VwdGlvbgoALQBf"
        "DABgAGEBAAdnZXROYW1lAQAUKClMamF2YS9sYW5nL1N0cmluZzsKAGMAZAcAZQwAZgBnAQAQamF2YS9sYW5nL1N0cmluZwEA"
        "CGhhc2hDb2RlAQADKClJCABpAQAQYmVmb3JlQ2hlY2twb2ludAoAYwBrDABsAFABAAZlcXVhbHMIAG4BAAxhZnRlclJlc3Rv"
        "cmUIAGYIAGwIAHIBAAh0b1N0cmluZwsAdAB1BwB2DABpAHcBABFvcmcvY3JhYy9SZXNvdXJjZQEAFShMb3JnL2NyYWMvQ29u"
        "dGV4dDspVgsAdAB5DABuAHcKAHsAfAcAfQwAfgB/AQAQamF2YS9sYW5nL1N5c3RlbQEAEGlkZW50aXR5SGFzaENvZGUBABUo"
        "TGphdmEvbGFuZy9PYmplY3Q7KUkKAIEAggcAgwwAhACFAQARamF2YS9sYW5nL0ludGVnZXIBAAd2YWx1ZU9mAQAWKEkpTGph"
        "dmEvbGFuZy9JbnRlZ2VyOwoAhwCIBwCJDACEAIoBABFqYXZhL2xhbmcvQm9vbGVhbgEAFihaKUxqYXZhL2xhbmcvQm9vbGVh"
        "bjsKAGMAjAwAhACNAQAmKExqYXZhL2xhbmcvT2JqZWN0OylMamF2YS9sYW5nL1N0cmluZzsSAAQAFwEACVNpZ25hdHVyZQEA"
        "FExqYXZhL2xhbmcvQ2xhc3M8Kj47AQAkTGphdmEvdXRpbC9MaXN0PExqYXZhL2xhbmcvT2JqZWN0Oz47AQAEQ29kZQEACkV4"
        "Y2VwdGlvbnMHAJUBACZqYXZhL2xhbmcvUmVmbGVjdGl2ZU9wZXJhdGlvbkV4Y2VwdGlvbgEAKyhMb3JnL2NyYWMvQ29udGV4"
        "dDwrTG9yZy9jcmFjL1Jlc291cmNlOz47KVYBABYoTG9yZy9jcmFjL1Jlc291cmNlOylWAQANU3RhY2tNYXBUYWJsZQEAEWxh"
        "bWJkYSRyZWdpc3RlciQwAQBmKExvcmcvY3JhYy9SZXNvdXJjZTtMamF2YS9sYW5nL09iamVjdDtMamF2YS9sYW5nL3JlZmxl"
        "Y3QvTWV0aG9kO1tMamF2YS9sYW5nL09iamVjdDspTGphdmEvbGFuZy9PYmplY3Q7BwCcAQATamF2YS9sYW5nL1Rocm93YWJs"
        "ZQEAJ0xvcmcvY3JhYy9Db250ZXh0PExvcmcvY3JhYy9SZXNvdXJjZTs+OwEAEEJvb3RzdHJhcE1ldGhvZHMIAKABAAoBLlJl"
        "c291cmNlCACiAQAJAS5Db250ZXh0CACkAQAGAS5Db3JlEACmAQBTKExqYXZhL2xhbmcvT2JqZWN0O0xqYXZhL2xhbmcvcmVm"
        "bGVjdC9NZXRob2Q7W0xqYXZhL2xhbmcvT2JqZWN0OylMamF2YS9sYW5nL09iamVjdDsPBQCoCgALAKkMAJkAmggAqwEAFG9y"
        "Zy5jcmFjIHByb3h5IGZvciABDwYArQoArgCvBwCwDAAYALEBACRqYXZhL2xhbmcvaW52b2tlL1N0cmluZ0NvbmNhdEZhY3Rv"
        "cnkBAJgoTGphdmEvbGFuZy9pbnZva2UvTWV0aG9kSGFuZGxlcyRMb29rdXA7TGphdmEvbGFuZy9TdHJpbmc7TGphdmEvbGFu"
        "Zy9pbnZva2UvTWV0aG9kVHlwZTtMamF2YS9sYW5nL1N0cmluZztbTGphdmEvbGFuZy9PYmplY3Q7KUxqYXZhL2xhbmcvaW52"
        "b2tlL0NhbGxTaXRlOw8GALMKALQAtQcAtgwAtwC4AQAiamF2YS9sYW5nL2ludm9rZS9MYW1iZGFNZXRhZmFjdG9yeQEAC21l"
        "dGFmYWN0b3J5AQDMKExqYXZhL2xhbmcvaW52b2tlL01ldGhvZEhhbmRsZXMkTG9va3VwO0xqYXZhL2xhbmcvU3RyaW5nO0xq"
        "YXZhL2xhbmcvaW52b2tlL01ldGhvZFR5cGU7TGphdmEvbGFuZy9pbnZva2UvTWV0aG9kVHlwZTtMamF2YS9sYW5nL2ludm9r"
        "ZS9NZXRob2RIYW5kbGU7TGphdmEvbGFuZy9pbnZva2UvTWV0aG9kVHlwZTspTGphdmEvbGFuZy9pbnZva2UvQ2FsbFNpdGU7"
        "AQAMSW5uZXJDbGFzc2VzBwC7AQAlamF2YS9sYW5nL2ludm9rZS9NZXRob2RIYW5kbGVzJExvb2t1cAcAvQEAHmphdmEvbGFu"
        "Zy9pbnZva2UvTWV0aG9kSGFuZGxlcwEABkxvb2t1cAAwAAsAAgAAAAQAEgA0ADUAAAASACAAIQABAI8AAAACAJAAEgA3ADoA"
        "AAASAA4ADwABAI8AAAACAJEABQAAAAUAQQACAJIAAAByAAcABAAAAGYqtwABKrsAB1m3AAm1AAoSC7YAEE0qK7oAFgAAAyy4"
        "ABq1AB4rugAiAAADLLgAGk4qK7oAIwAABCy4ABoSJAO9ABG2ACYBA70AKrYALLUAMiotEjYEvQARWQMqtAAeU7YAJrUAOLEA"
        "AAAAAJMAAAAEAAEAlAABAGkAdwACAJIAAAAWAAMAAgAAAAq7ADtZEj23AD+/AAAAAACPAAAAAgCWAAEAbgB3AAIAkgAAABYA"
        "AwACAAAACrsAO1kSPbcAP78AAAAAAI8AAAACAJYAIQA3AJcAAQCSAAAAnAAGAAQAAABgEgu2ABAEvQARWQMqtAAeUyorugBC"
        "AAC4AEVNKrQACiu5AEsCAFcqtAAKLLkASwIAVyq0ADgqtAAyBL0AKlkDLFO2ACxXpwAaTrsAU1kttgBVtwBZv067AFNZLbcA"
        "Wb+xAAIAMQBFAEgAUQAxAEUAVQBcAAEAmAAAABoAA/8ASAADBwALBwB0BwAqAAEHAFFMBwBcCRACAJkAmgACAJIAAAEaAAMA"
        "BwAAAPEttgBeOgUCNgYZBbYAYqsAAAAAfwAAAAWWFlJsAAAAcrLIf78AAABiusZeZwAAADIIzawbAAAAUlSfVRIAAABCGQUS"
        "aLYAapkARgM2BqcAQBkFEm22AGqZADYENganADAZBRJvtgBqmQAmBTYGpwAgGQUScLYAapkAFgY2BqcAEBkFEnG2AGqZAAYH"
        "NgYVBqoAAABWAAAAAAAAAAQAAAAhAAAAKgAAADMAAAA7AAAATCsquQBzAgABsCsquQB4AgABsCy4AHq4AICwLBkEAzKmAAcE"
        "pwAEA7gAhrAruACLugCOAACwuwA7WS22AF63AD+/AAAAAQCYAAAAFwAO/QBABwBjAQ8PDw8MIggIBwtAAQMJAJMAAAAEAAEA"
        "mwADAI8AAAACAJ0AngAAACQABQCsAAEAnwCsAAEAoQCsAAEAowCyAAMApQCnAKUArAABAKoAuQAAAAoAAQC6ALwAvgAZ",
}


def _deployment_zip():
    """Decode the pinned bytecode, assert every blob's SHA-256, and pack a Lambda zip."""
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
    raise AssertionError(f"log group {group} kept reappearing after its deletes")


def _poll(probe, timeout_s, interval_s=3.0):
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


def _wait_snapstart_on(lam, qualified, timeout_s=600):
    def _probe():
        cfg = lam.get_function(FunctionName=qualified)["Configuration"]
        if cfg.get("State") == "Failed":
            raise AssertionError(
                f"{qualified} entered State=Failed while optimizing the snapshot: "
                f"{cfg.get('StateReason')!r}"
            )
        status = (cfg.get("SnapStart") or {}).get("OptimizationStatus")
        return cfg if cfg.get("State") == "Active" and status == "On" else None

    cfg = _poll(_probe, timeout_s)
    assert cfg is not None, (
        f"{qualified} never reached State=Active with SnapStart.OptimizationStatus=='On' within "
        f"{timeout_s}s — snapshot optimization is a REQUIRED transition here, so a stall is a "
        f"failure and never a skip"
    )
    return cfg


def _invoke(lam, target, hold_ms):
    resp = lam.invoke(
        FunctionName=target, LogType="Tail",
        Payload=json.dumps({"holdMs": hold_ms}).encode(),
    )
    raw = resp["Payload"].read()
    assert resp["StatusCode"] == 200, f"{target}: StatusCode {resp['StatusCode']!r} {raw!r}"
    assert "FunctionError" not in resp, (
        f"{target} failed with FunctionError={resp.get('FunctionError')!r}: {raw!r}"
    )
    log = base64.b64decode(resp["LogResult"]).decode("utf8", "replace")
    body = json.loads(raw)
    body["_log"] = log
    return body


def _burst(lam, target, hold_ms):
    with concurrent.futures.ThreadPoolExecutor(max_workers=BURST) as ex:
        futures = [ex.submit(_invoke, lam, target, hold_ms) for _ in range(BURST)]
        return [f.result(timeout=300) for f in futures]


def _report_field(log, label):
    """Pull `<label>: <float> ms` out of a REPORT/RESTORE_REPORT line."""
    m = re.search(re.escape(label) + r":\s*([0-9]+(?:\.[0-9]+)?)\s*ms", log)
    return None if m is None else float(m.group(1))


def _all_streams(ctx, group):
    logs = ctx.client("logs")
    out = []
    for page in logs.get_paginator("describe_log_streams").paginate(logGroupName=group):
        out.extend(page["logStreams"])
    return out


def _stream_text(ctx, group, stream):
    # GetLogEvents has no botocore paginator, and it always returns a nextForwardToken even when
    # exhausted, so the loop terminates on a repeated token rather than on its absence.
    logs = ctx.client("logs")
    parts = []
    token = None
    for _ in range(50):
        kw = dict(logGroupName=group, logStreamName=stream, startFromHead=True, limit=1000)
        if token is not None:
            kw["nextToken"] = token
        page = logs.get_log_events(**kw)
        parts.extend(e["message"] for e in page["events"])
        nxt = page.get("nextForwardToken")
        if not page["events"] or nxt == token:
            break
        token = nxt
    return "".join(parts)


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Java 21 SnapStart restore runs org.crac hooks, replays one snapshotted init into each
    environment (a pre-checkpoint Random repeats; SecureRandom and UUIDs differ), and is logged and
    billed as a restore; the $LATEST twin, where SnapStart does not apply, is the control."""
    lam = ctx.client("lambda")
    zb = _deployment_zip()
    fn = ctx.unique_name("sim2real-behav-javasnap-")
    _create_function(lam, dict(
        FunctionName=fn, Runtime="java21", Handler="probe.SnapHandler",
        Role=_exec_role_arn(ctx), Code={"ZipFile": zb}, MemorySize=512, Timeout=60,
        Tags={"sim2real:managed": "true"},
    ))
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, fn))
    _wait_active(lam, fn)
    group = f"/aws/lambda/{fn}"

    # ---- the JVM identifies itself, and the CRaC API resolved to the platform's coordinator ----
    warm = _invoke(lam, fn, 0)
    assert warm["javaVersion"].startswith("21."), (
        f"the runtime reported java.version={warm['javaVersion']!r}; a java21 managed runtime must "
        f"report a 21.x JVM, and nothing below can be about a JVM if this is not one"
    )
    assert "OpenJDK 64-Bit Server VM" == warm["vmName"], (
        f"java.vm.name was {warm['vmName']!r}, not the HotSpot server VM the managed runtime ships"
    )
    assert warm["hookRegistration"] == "ok:org.crac.GlobalContextWrapper", (
        f"org.crac.Core.getGlobalContext() resolved to {warm['hookRegistration']!r}. It must be "
        f"org.crac.GlobalContextWrapper — the shipped org.crac API delegating to the platform's own "
        f"checkpoint coordinator. If the jar shadowed the runtime's implementation instead, the "
        f"hooks would silently never fire and every restore assertion below would be vacuous"
    )
    assert warm["beforeCheckpointCount"] == 0 and warm["afterRestoreCount"] == 0, (
        f"$LATEST is not a SnapStart target, so no checkpoint or restore hook may have run, but it "
        f"reported beforeCheckpointCount={warm['beforeCheckpointCount']!r} "
        f"afterRestoreCount={warm['afterRestoreCount']!r}"
    )

    # ---- publish a SnapStart version -----------------------------------------------------
    lam.update_function_configuration(
        FunctionName=fn, SnapStart={"ApplyOn": "PublishedVersions"}
    )
    cfg = _wait_active(lam, fn)
    assert (cfg.get("SnapStart") or {}).get("ApplyOn") == "PublishedVersions", (
        f"SnapStart.ApplyOn did not round-trip on $LATEST: {cfg.get('SnapStart')!r}"
    )
    version = lam.publish_version(FunctionName=fn)["Version"]
    qualified = f"{fn}:{version}"
    ver_cfg = _wait_snapstart_on(lam, qualified)
    assert (ver_cfg.get("SnapStart") or {}).get("OptimizationStatus") == "On", (
        f"the published version reports "
        f"SnapStart={(ver_cfg.get('SnapStart') or {})!r}, so nothing was snapshotted"
    )

    # ---- BURST concurrent restores from one snapshot --------------------------------------
    bodies = _burst(lam, qualified, HOLD_MS)

    restores = [b["restoreId"] for b in bodies]
    assert len(set(restores)) == BURST, (
        f"the afterRestore hook did not produce a distinct value per environment "
        f"({sorted(set(restores))!r} across {BURST} concurrent held invocations) — either the hook "
        f"ran once for all of them or the burst was served by fewer environments than it needs, "
        f"and in both cases every assertion below would be meaningless"
    )
    assert "no-restore-hook-ran" not in restores, (
        f"an invocation of the SnapStart version ran without afterRestore firing: {restores!r}"
    )
    assert all(b["afterRestoreCount"] == 1 for b in bodies), (
        f"afterRestore must run exactly once per restored environment, not once per invocation and "
        f"not zero times: {[b['afterRestoreCount'] for b in bodies]!r}"
    )
    assert all(b["beforeCheckpointCount"] == 1 for b in bodies), (
        f"every restored environment must observe beforeCheckpointCount==1, because the hook ran "
        f"ONCE at PublishVersion and its side effect was captured INSIDE the snapshot; got "
        f"{[b['beforeCheckpointCount'] for b in bodies]!r}. A 0 means no checkpoint hook ever ran "
        f"(so this is a cold start wearing a version number); anything above 1 means the snapshot "
        f"was re-taken per environment"
    )
    inits = {b["initId"] for b in bodies}
    assert len(inits) == 1, (
        f"the SnapStart version re-initialized instead of restoring: {BURST} environments reported "
        f"{len(inits)} distinct INIT_IDs {sorted(inits)!r}. A restored environment replays the "
        f"snapshotted module scope, never re-runs it"
    )

    # ---- the documented uniqueness hazard, asserted as a hazard ---------------------------
    # A re-init passes the uniqueness half and fails the shared-INIT_ID half; a snapshot without
    # the runtime's entropy reseeding does the reverse.
    first_draws = {b["firstDraw"] for b in bodies}
    assert len(first_draws) == 1, (
        f"a Random seeded before the checkpoint reported {len(first_draws)} distinct first draws "
        f"{sorted(first_draws)!r} across {BURST} restores"
    )
    next_draws = {b["nextDraw"] for b in bodies}
    assert len(next_draws) == 1, (
        f"the seeded Random's POST-restore draw differed across restored environments "
        f"({sorted(next_draws)!r}), so its internal seed field was NOT part of the memory image — "
        f"only the seed constant was. This assertion documents a HAZARD that must reproduce: every "
        f"restored environment continues the PRNG from the identical snapshotted state, which is "
        f"why AWS ships a SpotBugs rule against seeding a generator before the checkpoint"
    )
    secures = {b["secureRandomHex"] for b in bodies}
    assert len(secures) == BURST, (
        f"SecureRandom produced {len(secures)} distinct values across {BURST} restores "
        f"({sorted(secures)!r}); the runtime's reseeding carve-out must make it unique per resume "
        f"even though the ordinary heap around it is byte-identical"
    )
    uuids = {b["uuid"] for b in bodies}
    assert len(uuids) == BURST, (
        f"UUID.randomUUID() repeated across restored environments: {sorted(uuids)!r}. This is the "
        f"exact production failure the carve-out exists to prevent"
    )
    assert uuids.isdisjoint(inits), (
        f"a post-restore UUID collided with the snapshotted INIT_ID {sorted(inits)!r} — no restored "
        f"environment may report another environment's identity"
    )

    # ---- restore accounting, which lives only in the log ----------------------------------
    tail = bodies[0]["_log"]
    assert "RESTORE_START Runtime Version:" in tail, (
        f"the restored invocation's log has no RESTORE_START line; it began:\n{tail[:600]!r}"
    )
    assert "RESTORE_REPORT" in tail, f"no RESTORE_REPORT line in the restored invocation's log:\n{tail[:600]!r}"
    report_line = next((ln for ln in tail.splitlines() if ln.startswith("REPORT RequestId:")), None)
    assert report_line is not None, f"no REPORT line in the tail log:\n{tail[:600]!r}"
    assert "Init Duration" not in report_line, (
        f"the REPORT line for a restored invocation must NOT carry Init Duration — the init it "
        f"replaced happened at snapshot time: {report_line!r}"
    )
    restore_ms = _report_field(report_line, "Restore Duration")
    billed_ms = _report_field(report_line, "Billed Restore Duration")
    assert restore_ms is not None and restore_ms > 0, (
        f"REPORT carried no positive `Restore Duration`: {report_line!r}"
    )
    assert billed_ms is not None and billed_ms > 0, (
        f"REPORT carried no positive `Billed Restore Duration`: {report_line!r}"
    )
    assert billed_ms <= restore_ms, (
        f"Billed Restore Duration {billed_ms!r} ms exceeds Restore Duration {restore_ms!r} ms; "
        f"billing excludes the out-of-MicroVM part of the restore, so it can never be larger"
    )
    restore_report_line = next(ln for ln in tail.splitlines() if ln.startswith("RESTORE_REPORT"))
    assert _report_field(restore_report_line, "Restore Duration") == restore_ms, (
        f"RESTORE_REPORT and REPORT disagree on Restore Duration: {restore_report_line!r} vs "
        f"{report_line!r}"
    )

    # ---- off-response: BURST restores each wrote their own stream, and the replaced init
    # ---- was recorded exactly once, in a stream of its own -------------------------------
    def _streams_ready():
        got = [s for s in _all_streams(ctx, group) if f"[{version}]" in s["logStreamName"]]
        return got if len(got) >= BURST + 1 else None

    ver_streams = _poll(_streams_ready, 180, 5.0)
    assert ver_streams is not None, (
        f"log group {group} never showed the {BURST + 1} version-[{version}] streams a "
        f"{BURST}-way restore plus one snapshot init must produce; saw "
        f"{[s['logStreamName'] for s in _all_streams(ctx, group)]!r}"
    )
    texts = {s["logStreamName"]: _stream_text(ctx, group, s["logStreamName"]) for s in ver_streams}
    with_restore = [n for n, t in texts.items() if "RESTORE_REPORT" in t]
    assert len(with_restore) == BURST, (
        f"{len(with_restore)} of the version's log streams contain a RESTORE_REPORT, expected "
        f"exactly {BURST} — one per restored environment. Streams seen: "
        f"{ {n: t[:120] for n, t in texts.items()} !r}"
    )
    init_streams = [n for n, t in texts.items() if "INIT_REPORT Init Duration:" in t]
    assert len(init_streams) == 1, (
        f"the replaced init must be recorded exactly once, in its own stream written when the "
        f"snapshot was created; found {len(init_streams)} streams with an INIT_REPORT: "
        f"{init_streams!r}"
    )
    assert "RESTORE_REPORT" not in texts[init_streams[0]], (
        f"the snapshot-init stream {init_streams[0]!r} also contains a RESTORE_REPORT, so init and "
        f"restore were not separated: {texts[init_streams[0]][:400]!r}"
    )

    # ---- control: the identical bytecode on $LATEST, where SnapStart does not apply -------
    latest = _burst(lam, fn, HOLD_MS)
    latest_inits = [b["initId"] for b in latest]
    assert len(set(latest_inits)) == BURST, (
        f"the non-SnapStart control did not re-initialize between cold environments: "
        f"{latest_inits!r}. Without that, the version's shared INIT_ID could just mean this "
        f"handler mints a constant"
    )
    assert set(latest_inits).isdisjoint(inits), (
        f"a $LATEST environment reported the snapshotted version's INIT_ID {sorted(inits)!r}"
    )
    assert all(b["afterRestoreCount"] == 0 for b in latest), (
        f"afterRestore fired on $LATEST, where SnapStart is not applied: "
        f"{[b['afterRestoreCount'] for b in latest]!r}"
    )
    assert all(b["beforeCheckpointCount"] == 0 for b in latest), (
        f"beforeCheckpointCount was non-zero on $LATEST: no snapshot, no checkpoint hook; got "
        f"{[b['beforeCheckpointCount'] for b in latest]!r}"
    )
    assert {b["firstDraw"] for b in latest} == first_draws, (
        f"the control's seeded first draw {sorted({b['firstDraw'] for b in latest})!r} differs from "
        f"the version's {sorted(first_draws)!r}; a fixed seed is deterministic with or without "
        f"SnapStart, and pinning that is what makes the restored PRNG assertion about RESTORE"
    )
    latest_report = next(
        ln for ln in latest[0]["_log"].splitlines() if ln.startswith("REPORT RequestId:")
    )
    assert "Init Duration" in latest_report, (
        f"a cold $LATEST invocation's REPORT must carry Init Duration: {latest_report!r}"
    )
    assert "Restore Duration" not in latest_report, (
        f"a $LATEST invocation's REPORT must NOT carry Restore Duration — nothing was restored: "
        f"{latest_report!r}"
    )
    assert "RESTORE_REPORT" not in latest[0]["_log"], (
        f"a $LATEST invocation emitted a RESTORE_REPORT line: {latest[0]['_log'][:400]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
