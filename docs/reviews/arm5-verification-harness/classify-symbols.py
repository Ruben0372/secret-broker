"""Classify undefined symbols as capability-bearing or inert.

Used for the correction-2 delta requirement to confirm that the symbols a
different toolchain adds to the golden set carry no capability.

Usage: python3 classify-symbols.py <symbols-file> [<baseline-file>]
  With a baseline, only symbols absent from it are classified (the delta).

Classification rests on what each symbol class can actually do:

  autolink   __swift_FORCE_LOAD_$_<overlay>. A linker directive emitted because
             an imported module's overlay autolinks, not because the module
             calls anything. Inert BY ITSELF, but the overlay NAME still matters:
             a security, credential, or IPC overlay the daemon has no business
             linking is a finding even though the marker proves no call. Those
             names are escalated below rather than waved through.

  stdlib     Mangled Swift symbols (_$s / _$ss prefixes) for metadata, protocol
             witnesses, and generic plumbing. Type-system machinery; carries no
             syscall or framework reach.

  runtime    swift_* entry points: ARC, error handling, task machinery, metadata
             lookup. Runtime support, no external capability.

  libc-inert memcpy, ___chkstk_darwin and friends. Memory and stack plumbing.

  CAPABILITY Anything matching the denylist families, or naming a framework
             class through Objective-C interop. These are the real signal.
"""
import re
import sys

# Overlays that ordinary Foundation and CryptoKit use transitively. Presence of
# these as autolink markers is expected and proves nothing about behaviour.
BENIGN_OVERLAYS = {
    "swiftCoreFoundation", "swiftDispatch", "swiftFoundation", "swiftObjectiveC",
    "swift_Builtin_float", "swiftDarwin", "swiftos", "swiftCoreGraphics",
    "swift_Concurrency", "swift_StringProcessing", "swift_RegexParser",
    "swiftUniformTypeIdentifiers", "swiftIOKit", "swiftXPC",
}

# Overlays that would mean the module links a framework it should not. Not proof
# of a call, but a blocking question for a credential custodian.
ESCALATE_OVERLAYS = {
    "swiftSecurity", "swiftLocalAuthentication", "swiftCryptoTokenKit",
    "swiftNetwork", "swiftSystemConfiguration", "swiftServiceManagement",
}

# Mach-O symbols carry a leading underscore, and underscore is a word character,
# so a \b-anchored pattern such as \bdlopen\b never matches _dlopen. An earlier
# version of this file made exactly that mistake: _dlopen fell through to REVIEW
# as "unrecognised" instead of being named as dynamic symbol resolution. It still
# blocked, because REVIEW is non-zero, but a reviewer would have been told the
# wrong thing about why. Match against the underscore-stripped name by prefix.
C_CAPABILITY_PREFIXES = [
    (("dlopen", "dlsym", "dladdr", "dlclose"), "dynamic symbol resolution"),
    (("posix_spawn", "execve", "execvp", "execl", "fork", "popen", "system"), "process execution"),
    (("setenv", "putenv", "unsetenv", "getenv", "environ"), "environment access"),
    (("SecItem", "SecKeychain", "SecAccess", "SecTrust", "SecCertificate"), "keychain or trust services"),
]

OBJC_CAPABILITY_CLASSES = [
    (("NSTask",), "subprocess via Foundation"),
    (("NSProcessInfo",), "process info and environment"),
    (("NSURLSession", "NSStream", "NSURLConnection"), "network"),
    (("NSFileManager", "NSFileHandle"), "filesystem"),
]

OBJC_CLASS_RE = re.compile(r"_OBJC_CLASS_\$_(\w+)")


def classify(symbol):
    core = symbol.lstrip("_")
    objc = OBJC_CLASS_RE.search(symbol)
    if objc:
        for names, why in OBJC_CAPABILITY_CLASSES:
            if objc.group(1) in names:
                return "CAPABILITY", why
    for prefixes, why in C_CAPABILITY_PREFIXES:
        if core.startswith(prefixes):
            return "CAPABILITY", why
    m = re.match(r"_*swift_FORCE_LOAD_\$_(\w+)", symbol)
    if m:
        overlay = m.group(1)
        if overlay in ESCALATE_OVERLAYS:
            return "CAPABILITY", f"links {overlay}, a framework the daemon should not need"
        if overlay in BENIGN_OVERLAYS:
            return "autolink", f"{overlay}, transitively autolinked, no call implied"
        return "REVIEW", f"{overlay}, overlay not in the reviewed set; classify before accepting"
    if symbol.startswith("_$s"):
        return "stdlib", "mangled metadata or protocol witness"
    if re.match(r"_*swift_\w+", symbol):
        return "runtime", "Swift runtime support entry point"
    if core in {"memcpy", "__chkstk_darwin", "chkstk_darwin", "memmove", "memset", "bzero", "__stack_chk_fail", "stack_chk_fail", "__stack_chk_guard"}:
        return "libc-inert", "memory or stack plumbing"
    return "REVIEW", "unrecognised; classify before accepting"


def load(path):
    with open(path) as handle:
        return [line.strip() for line in handle if line.strip()]


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    symbols = load(sys.argv[1])
    if len(sys.argv) > 2:
        baseline = set(load(sys.argv[2]))
        symbols = [s for s in symbols if s not in baseline]
        print(f"delta against baseline: {len(symbols)} symbol(s)\n")

    buckets = {}
    for symbol in sorted(set(symbols)):
        verdict, why = classify(symbol)
        buckets.setdefault(verdict, []).append((symbol, why))

    for verdict in ["CAPABILITY", "REVIEW", "autolink", "stdlib", "runtime", "libc-inert"]:
        if verdict not in buckets:
            continue
        print(f"{verdict}: {len(buckets[verdict])}")
        show = buckets[verdict] if verdict in ("CAPABILITY", "REVIEW", "autolink") else buckets[verdict][:3]
        for symbol, why in show:
            print(f"    {symbol}\n        {why}")
        if len(buckets[verdict]) > len(show):
            print(f"    ... and {len(buckets[verdict]) - len(show)} more")
        print()

    blocking = len(buckets.get("CAPABILITY", [])) + len(buckets.get("REVIEW", []))
    print("VERDICT:", "CLEAN, nothing capability-bearing" if blocking == 0
          else f"{blocking} symbol(s) need a decision before acceptance")
    return 1 if blocking else 0


if __name__ == "__main__":
    sys.exit(main())
