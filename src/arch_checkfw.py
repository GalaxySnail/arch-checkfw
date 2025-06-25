# SPDX-License-Identifier: GPL-2.0-or-later
import os
import sys
import argparse
import itertools
import re
import subprocess


def detect_drivers_modaliases():
    """
    Basically ported from mkinitcpio's autodetect hook.

    ref: https://github.com/archlinux/mkinitcpio/blob/v39.2/install/autodetect#L15
    """
    drivers = set()
    modaliases = set()

    for root, dirs, files in os.walk("/sys/devices"):
        if "uevent" not in files:
            continue
        with open(os.path.join(root, "uevent"), encoding="UTF-8") as f:
            for line in f:
                match = re.match(r"(DRIVER|MODALIAS)=(.+)", line.rstrip())
                if match is None:
                    continue
                field = match.group(1)
                value = match.group(2)
                if field == "DRIVER":
                    drivers.add(value)
                elif field == "MODALIAS":
                    modaliases.add(value)

    return sorted(drivers) + sorted(modaliases)


def resolve_modalias(mods, kernel_version=None):
    assert not isinstance(mods, str)

    modprobe_cmd = ["modprobe"]
    if kernel_version:
        modprobe_cmd.extend(["-S", kernel_version])

    modprobe_cmd.append("-qaR")
    modprobe_cmd.extend(mods)

    result = subprocess.run(modprobe_cmd, stdout=subprocess.PIPE,
                            encoding="UTF-8", check=False)
    return sorted(set(result.stdout.splitlines()))


def resolve_module_depends(mods, kernel_version=None):
    assert not isinstance(mods, str)

    def get_depends(mod):
        modinfo_cmd = ["modinfo", "-F", "depends"]
        if kernel_version:
            modinfo_cmd.extend(["-k", kernel_version])
        modinfo_cmd.append(mod)

        result = subprocess.run(modinfo_cmd, stdout=subprocess.PIPE,
                                encoding="UTF-8", check=True)
        return result.stdout.strip().split(",")

    resolved = set()
    about_to_resolve = list(mods)

    while about_to_resolve:
        mod = about_to_resolve.pop()
        if not mod:
            continue
        if mod in resolved:
            continue
        depends = get_depends(mod)
        about_to_resolve.extend(depends)
        resolved.add(mod)

    return sorted(resolved)


def auto_detect_modules(resolve_deps=True):
    mods = detect_drivers_modaliases()
    mods = resolve_modalias(mods)
    if resolve_deps:
        mods = resolve_module_depends(mods)
    return mods


def get_firmware(mod, kernel_version=None):
    modinfo_cmd = ["modinfo", "-F", "firmware"]
    if kernel_version:
        modinfo_cmd.extend(["-k", kernel_version])
    modinfo_cmd.append(mod)

    result = subprocess.run(modinfo_cmd, stdout=subprocess.PIPE,
                            encoding="UTF-8", check=True)
    return result.stdout.splitlines()


def search_firmware(fws):
    assert not isinstance(fws, str)

    pacfiles_cmd = ["pacfiles", "-q"]
    pacfiles_cmd.extend(f"usr/lib/firmware/{fw}*" for fw in fws)

    result = subprocess.run(pacfiles_cmd, stdout=subprocess.PIPE,
                            encoding="UTF-8", check=False)
    if result.returncode not in [0, 1]:
        result.check_returncode()

    return set(result.stdout.splitlines())


def check_pacfiles_db():
    DBPATH = "/var/lib/pacman/sync"
    if not (os.access(f"{DBPATH}/core.pacfiles", os.F_OK)
            and os.access(f"{DBPATH}/extra.pacfiles", os.F_OK)):
        print("Please run `sudo pacfiles -y` to update databases.",
              file=sys.stderr)
        sys.exit(1)

    def check_mtime(name):
        db = f"{name}.db"
        files = f"{name}.files"
        pacfiles = f"{name}.pacfiles"

        db_mtime = os.stat(f"{DBPATH}/{db}").st_mtime
        files_mtime = os.stat(f"{DBPATH}/{files}").st_mtime
        pacfiles_mtime = os.stat(f"{DBPATH}/{pacfiles}").st_mtime

        if pacfiles_mtime < files_mtime:
            print(f"[warning] {pacfiles} is older than {files}. "
                  "Please run `sudo pacfiles --update-db` first.",
                  file=sys.stderr)

        mtime_delta_s = files_mtime - db_mtime
        if abs(mtime_delta_s) > 2 * 60 * 60:  # 2 hours
            from datetime import timedelta
            mtime_delta = timedelta(seconds=abs(mtime_delta_s))
            print(f"[warning] {files} is {mtime_delta} "
                  f"{'newer' if mtime_delta_s > 0 else 'older'} than {db}.",
                  file=sys.stderr)

    check_mtime("core")
    check_mtime("extra")


def get_argparser():
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", action="count", default=0,
                        help="show all detected modules; give twice to show "
                             "all firmware files required by modules")
    return parser


def main():
    parser = get_argparser()
    args = parser.parse_args()

    check_pacfiles_db()

    fw_module_map = {}

    for m in auto_detect_modules(False):
        if args.verbose >= 1:
            print(f"--- {m} ---")

        fws = get_firmware(m)
        if args.verbose >= 2:
            for fw in fws:
                print(fw)

        packages = set()
        # use batched to avoid argv size limit
        for batch_fws in itertools.batched(fws, 100):
            packages |= search_firmware(batch_fws)

        for package in sorted(packages):
            if args.verbose >= 1:
                print(f"requires package: {package}")
            fw_module_map.setdefault(package, []).append(m)

    if args.verbose >= 1:
        print()

    for package, mods in fw_module_map.items():
        print(f"{package} is required by {', '.join(mods)}")


if __name__ == "__main__":
    main()
