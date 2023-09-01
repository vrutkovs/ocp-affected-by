#!/usr/bin/env python
import subprocess
import sys
import pprint

# pip install nvdlib
import nvdlib
# pip install cpe
import cpe
# pip install semver
import semver

pp = pprint.PrettyPrinter(indent=4)

if len(sys.argv) < 2:
  print("Usage: ocp-affected-by.py <release image pullspec> <CVE>")
  sys.exit(1)


def find_golang_in_ocp_binaries(release):
  binaries_found = {}
  # n = 0

  print(f"Listing components in {release}")
  output = subprocess.check_output(["oc", "adm", "release", "info", release, "-o", 'jsonpath={range .references.spec.tags[*]}{.name} {.from.name}{"\\n"}{end}'])
  for component in output.decode('utf-8').strip().split('\n'):
    name, pull_spec = component.split(' ')

    print(f"Pulling {name} ({pull_spec})")
    subprocess.check_call(["podman", "create", "--name=component", pull_spec])

    try:
      container_dir_bytes = subprocess.check_output(["buildah", "mount", "component"])
      container_dir = container_dir_bytes.decode('utf-8').strip()
      cmd = ["find -type f -executable | xargs -n1 go version"]
      binaries = subprocess.run(cmd, capture_output=True, shell=True, executable="/bin/bash", cwd=container_dir)
      for binary in binaries.stdout.decode('utf-8').strip().split('\n'):
        print(f"Found binary {binary}")
        path, go_signature = binary.split(": ")
        if not go_signature.startswith("go"):
          continue
        go_version = go_signature.split(" ")[0].split("go")[1]
        binaries_found[name] = {
          "path": path,
          "go_version": go_version
        }
    finally:
      print("Unmounting")
      subprocess.check_call(["buildah", "unmount", "component"])
      subprocess.check_call(["podman", "rm", "-f", "component"])

    # n += 1
    # if n > 10:
    #   break

  go_versions = {}
  for pull_spec, obj in binaries_found.items():
    go_version = obj["go_version"]
    if not go_version in go_versions:
      go_versions[go_version] = []
    go_versions[go_version].append({"pull_spec": pull_spec, "path": obj["path"]})

  return go_versions

def find_cpes_for_cve(cve_id):
  print(f"Fetching {cve_id} details")
  r = nvdlib.searchCVE(cveId=cve_id)
  if len(r) == 0:
    print(f"{cve} not found")
    sys.exit(1)

  cve = r[0]
  cpes = []
  for c in cve.configurations:
    for n in c.nodes:
      for m in n.cpeMatch:
        if m.vulnerable == False:
          continue
        cpes.append(m)

  return cpes

def does_cpe_match_goversion(cpe, go_version):
  go_semver = semver.Version.parse(go_version)
  if hasattr(cpe, "versionEndExcluding"):
    cpe_end_semver = semver.Version.parse(cpe.versionEndExcluding)
    if hasattr(cpe, "versionStartIncluding"):
      cpe_start_semver = semver.Version.parse(cpe.versionStartIncluding)
      if cpe_start_semver <= go_version and cpe_end_semver > go_semver:
        return True
    elif cpe_end_semver > go_semver:
      return True
  return False

release = sys.argv[1]
cve_id = sys.argv[2]

cpes = find_cpes_for_cve(cve_id)

go_versions = find_golang_in_ocp_binaries(release)
pp.pprint(f"Found golang versions: {go_versions.keys()}")

found_vulnerable = False
for go_version, obj in go_versions.items():
  for cpe in cpes:
    if does_cpe_match_goversion(cpe, go_version):
      print(f"Found vulnerable go {go_version} for")
      pp.pprint(cpe)
      for affected in obj:
        print(f"\t{affected['pull_spec']}: {affected['path']}")
      found_vulnerable = True

if not found_vulnerable:
  pp.pprint("No vulnerable images found")
