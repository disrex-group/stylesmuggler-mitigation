#!/usr/bin/env python3
"""Make Magento's DI code scanners refuse to run outside CLI.

StyleSmuggler's second stage reaches a variable-path include/require inside
Magento's dependency-injection compiler classes. Those classes exist only to
serve `bin/magento setup:di:compile` and are never legitimately reached over
HTTP, so refusing non-CLI execution removes the primitive at no functional cost.

Idempotent. Safe to re-run after every deploy, which you must do: setup/ ships
from magento/magento2-base and `composer install` reverts these files.

Usage:
    stylesmuggler-harden.py [--check] [--revert] <magento-root> [<magento-root> ...]

Exit codes: 0 ok, 1 a target was missing or unhardened (with --check), 2 usage.
"""
import argparse
import os
import sys

MARKER = "StyleSmuggler mitigation"

GUARD = (
    "        // StyleSmuggler mitigation: this DI scanner only ever runs from\n"
    "        // bin/magento setup:di:compile. Reaching it over HTTP means the\n"
    "        // include below is being driven as a code-execution primitive.\n"
    "        // Remove once an upstream fix is applied. See disrex-group/stylesmuggler-mitigation\n"
    "        if (PHP_SAPI !== 'cli') {\n"
    "            throw new \\RuntimeException('Magento DI scanners are CLI-only.');\n"
    "        }\n"
)

# (relative path, list of accepted method signatures across 2.4.x)
TARGETS = [
    (
        "setup/src/Magento/Setup/Module/Di/Code/Scanner/ArrayScanner.php",
        ["public function collectEntities(array $files)"],
    ),
    (
        "setup/src/Magento/Setup/Module/Di/Code/Reader/ClassesScanner.php",
        [
            "private function includeClass(string $className, string $fileItemPath): bool",
            "private function includeClass($className, $fileItemPath)",
        ],
    ),
    (
        "setup/src/Magento/Setup/Module/Di/Code/Scanner/XmlInterceptorScanner.php",
        ["protected function _handleControllerClassName($className)"],
    ),
]


def _read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _write(path, text):
    tmp = path + ".stylesmuggler.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.replace(tmp, path)


def process(root, mode):
    done, already, missing = [], [], []
    for rel, signatures in TARGETS:
        path = os.path.join(root, rel)
        if not os.path.isfile(path):
            missing.append(rel)
            continue
        try:
            src = _read(path)
        except OSError as exc:
            missing.append(f"{rel} ({exc.strerror})")
            continue

        hardened = MARKER in src

        if mode == "check":
            (already if hardened else missing).append(rel)
            continue

        if mode == "revert":
            if not hardened:
                already.append(rel)
                continue
            start = src.index("        // " + MARKER)
            end = src.index("        }\n", src.index("if (PHP_SAPI", start)) + len("        }\n")
            out = src[:start] + src[end:]
            # drop the blank line the guard left behind
            out = out.replace("{\n\n        $output", "{\n        $output")
            _write(path, out)
            done.append(rel)
            continue

        if hardened:
            already.append(rel)
            continue
        sig = next((s for s in signatures if s in src), None)
        if sig is None:
            missing.append(f"{rel} (unrecognised method signature)")
            continue
        brace = src.index("{", src.index(sig) + len(sig))
        _write(path, src[: brace + 1] + "\n" + GUARD + src[brace + 1 :])
        done.append(rel)
    return done, already, missing


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--check", action="store_true", help="report state, change nothing")
    g.add_argument("--revert", action="store_true", help="remove the guard")
    ap.add_argument("roots", nargs="+", metavar="MAGENTO_ROOT")
    args = ap.parse_args()

    mode = "check" if args.check else "revert" if args.revert else "apply"
    verb = {"check": "hardened", "revert": "reverted", "apply": "hardened"}[mode]
    rc = 0

    for root in args.roots:
        root = root.rstrip("/")
        if not os.path.isfile(os.path.join(root, "app/etc/env.php")):
            print(f"{root}: not a Magento root, skipped")
            rc = 1
            continue
        done, already, missing = process(root, mode)
        if mode == "check":
            print(f"{root}: {len(already)}/{len(TARGETS)} guarded")
        else:
            print(f"{root}: {verb}={len(done)} unchanged={len(already)} problems={len(missing)}")
        for m in missing:
            print(f"  ! {m}")
            rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main())
