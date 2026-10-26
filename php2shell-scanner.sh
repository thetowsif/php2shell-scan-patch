#!/usr/bin/env bash
#
# php2shell-scan.sh — Universal PHP2Shell vulnerability scanner
# Detects CVE-2026-109618 / CVE-2026-109619 ("PHP2Shell") across:
#   - the host's native PHP install (CLI + php-fpm)
#   - every running Docker container
#   - every pod/container in any reachable Kubernetes cluster (if kubectl is configured)
#
# Patched versions: 8.5.12, 8.4.27, 8.3.36, 8.2.35
# Vulnerable: all PHP 5.4 - 8.5.11, and anything on 8.1 or older (no patch exists, EOL)
#
# Author:  Towsif Ibny Hassan (@thetowsif)
# GitHub:  https://github.com/thetowsif
# Contact: towsifibnyhassan@gmail.com
#
# Usage: ./php2shell-scan.sh
#   Run as root (or with docker/kubectl permissions) for a complete scan.
#   Exit code 0 = clean, 1 = vulnerable target(s) found.

set -u

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

AUTHOR="Towsif Ibny Hassan (@thetowsif)"
AUTHOR_GITHUB="https://github.com/thetowsif"
AUTHOR_CONTACT="towsifibnyhassan@gmail.com"

VULN_COUNT=0
OK_COUNT=0
declare -a VULN_LIST=()
declare -a OK_LIST=()
declare -A SEEN_SOURCES=()   # dedupe targets found via multiple lookup methods

VERSION_RE='^[0-9]+\.[0-9]+\.[0-9]+$'

# --- version comparison: returns 0 (true) if $1 < $2, using sort -V ---
version_lt() {
  [ "$1" = "$2" ] && return 1
  [ "$(printf '%s\n%s' "$1" "$2" | sort -V | head -n1)" = "$1" ]
}

# --- decide if a given PHP version string is vulnerable ---
# args: version (e.g. 8.3.35), source label (for reporting)
check_version() {
  local ver="$1"
  local src="$2"

  # dedupe: same source label already processed (e.g. same binary found two ways)
  if [ -n "${SEEN_SOURCES[$src]:-}" ]; then
    return
  fi
  SEEN_SOURCES[$src]=1

  # validate it's actually a clean X.Y.Z version string before trusting it.
  # anything else (empty, error text, exec failures, etc.) is skipped, never guessed at.
  if [ -z "$ver" ] || ! [[ "$ver" =~ $VERSION_RE ]]; then
    return  # not a PHP target, or couldn't read a clean version — skip silently
  fi

  local major_minor
  major_minor=$(echo "$ver" | cut -d. -f1,2)

  local patched=""
  case "$major_minor" in
    8.5) patched="8.5.12" ;;
    8.4) patched="8.4.27" ;;
    8.3) patched="8.3.36" ;;
    8.2) patched="8.2.35" ;;
    *)
      # 8.1 and below (or anything unrecognized/older) -> no patch exists, EOL, always vulnerable
      VULN_LIST+=("$src :: PHP $ver (EOL branch $major_minor, NO PATCH AVAILABLE - must upgrade to 8.2.35+)")
      VULN_COUNT=$((VULN_COUNT+1))
      return
      ;;
  esac

  if version_lt "$ver" "$patched"; then
    VULN_LIST+=("$src :: PHP $ver (vulnerable, needs >= $patched)")
    VULN_COUNT=$((VULN_COUNT+1))
  else
    OK_LIST+=("$src :: PHP $ver (patched)")
    OK_COUNT=$((OK_COUNT+1))
  fi
}

echo -e "${BOLD}=================================================================${NC}"
echo -e "${BOLD} PHP2Shell Universal Scanner (CVE-2026-109618 / CVE-2026-109619)${NC}"
echo " $(date)"
echo " Host: $(hostname 2>/dev/null || echo unknown)"
echo "-----------------------------------------------------------------"
echo -e " Author : ${CYAN}${AUTHOR}${NC}"
echo " GitHub : ${AUTHOR_GITHUB}"
echo " Contact: ${AUTHOR_CONTACT}"
echo -e "${BOLD}=================================================================${NC}"
echo

# ---------------------------------------------------------
# 1. Host-level PHP (CLI + every php-fpm binary found)
# ---------------------------------------------------------
echo -e "${BOLD}--- [1/3] Host PHP ---${NC}"

if command -v php >/dev/null 2>&1; then
  HOST_VER=$(php -r 'echo PHP_VERSION;' 2>/dev/null)
  check_version "$HOST_VER" "host:php-cli ($(command -v php))"
else
  echo "  no system 'php' binary found"
fi

# find every php-fpmX.Y binary, deduped by resolved real path
declare -A FPM_PATHS=()
while IFS= read -r b; do
  p=$(command -v "$b" 2>/dev/null)
  [ -n "$p" ] && FPM_PATHS["$p"]=1
done < <(compgen -c 2>/dev/null | grep -E '^php-fpm[0-9]' | sort -u)

while IFS= read -r p; do
  [ -n "$p" ] && FPM_PATHS["$p"]=1
done < <(find /usr/sbin /usr/bin /usr/local/sbin /usr/local/bin -maxdepth 1 -name 'php-fpm*' -type f 2>/dev/null)

for fpm_path in "${!FPM_PATHS[@]}"; do
  FPM_VER=$("$fpm_path" -v 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
  check_version "$FPM_VER" "host:$fpm_path"
done

echo

# ---------------------------------------------------------
# 2. Every Docker container
# ---------------------------------------------------------
echo -e "${BOLD}--- [2/3] Docker Containers ---${NC}"

if ! command -v docker >/dev/null 2>&1; then
  echo "  docker not found on this host, skipping"
elif ! docker info >/dev/null 2>&1; then
  echo "  docker daemon not reachable (permissions or not running), skipping"
else
  DOCKER_FOUND=0
  while IFS=$'\t' read -r cname cimage; do
    [ -z "$cname" ] && continue
    DOCKER_FOUND=$((DOCKER_FOUND+1))

    # only trust output if the exec actually succeeded (exit 0) AND looks like a version
    CVER=$(docker exec "$cname" php -r 'echo PHP_VERSION;' 2>/dev/null)
    RC=$?
    if [ $RC -ne 0 ] || ! [[ "$CVER" =~ $VERSION_RE ]]; then
      # fall back to php-fpm -v, but only if the binary actually exists in the container
      CVER=$(docker exec "$cname" sh -c 'command -v php-fpm >/dev/null 2>&1 && php-fpm -v 2>/dev/null' 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    fi

    if [[ "$CVER" =~ $VERSION_RE ]]; then
      check_version "$CVER" "docker:$cname ($cimage)"
    fi
    # else: no php in this container (db, cache, proxy, etc.) — skip silently, not a PHP target
  done < <(docker ps --format '{{.Names}}\t{{.Image}}' 2>/dev/null)

  [ "$DOCKER_FOUND" -eq 0 ] && echo "  no running containers found"
fi

echo

# ---------------------------------------------------------
# 3. Every pod/container in any reachable Kubernetes cluster
# ---------------------------------------------------------
echo -e "${BOLD}--- [3/3] Kubernetes Pods ---${NC}"

if ! command -v kubectl >/dev/null 2>&1; then
  echo "  kubectl not found on this host, skipping"
elif ! kubectl cluster-info >/dev/null 2>&1; then
  echo "  no reachable Kubernetes cluster (kubeconfig/context not set), skipping"
else
  CTX=$(kubectl config current-context 2>/dev/null || echo "unknown-context")
  echo "  cluster context: $CTX"

  K8S_FOUND=0
  # namespace\tpod\tcontainer, one per running container across all namespaces
  while IFS=$'\t' read -r ns pod ctr; do
    [ -z "$ns" ] && continue
    K8S_FOUND=$((K8S_FOUND+1))
    label="k8s:${ns}/${pod}/${ctr}"

    CVER=$(kubectl exec -n "$ns" "$pod" -c "$ctr" -- php -r 'echo PHP_VERSION;' 2>/dev/null)
    RC=$?
    if [ $RC -ne 0 ] || ! [[ "$CVER" =~ $VERSION_RE ]]; then
      CVER=$(kubectl exec -n "$ns" "$pod" -c "$ctr" -- sh -c 'command -v php-fpm >/dev/null 2>&1 && php-fpm -v 2>/dev/null' 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    fi

    if [[ "$CVER" =~ $VERSION_RE ]]; then
      # include the pod's image for traceability
      img=$(kubectl get pod -n "$ns" "$pod" -o jsonpath="{.spec.containers[?(@.name=='$ctr')].image}" 2>/dev/null)
      check_version "$CVER" "$label ($img)"
    fi
    # else: no php in this container — skip silently, not a PHP target
  done < <(kubectl get pods --all-namespaces -o go-template='{{range .items}}{{$ns := .metadata.namespace}}{{$pod := .metadata.name}}{{range .spec.containers}}{{$ns}}{{"\t"}}{{$pod}}{{"\t"}}{{.name}}{{"\n"}}{{end}}{{end}}' 2>/dev/null)

  [ "$K8S_FOUND" -eq 0 ] && echo "  no pods found (or insufficient RBAC permissions to list/exec)"
fi

echo
echo -e "${BOLD}=================================================================${NC}"
echo -e "${BOLD} SUMMARY${NC}"
echo -e "${BOLD}=================================================================${NC}"

if [ ${#VULN_LIST[@]} -gt 0 ]; then
  echo
  echo -e "${RED}VULNERABLE (${VULN_COUNT}) - fix these now:${NC}"
  for line in "${VULN_LIST[@]}"; do
    echo -e "  ${RED}[VULN]${NC} $line"
  done
fi

if [ ${#OK_LIST[@]} -gt 0 ]; then
  echo
  echo -e "${GREEN}PATCHED (${OK_COUNT}):${NC}"
  for line in "${OK_LIST[@]}"; do
    echo -e "  ${GREEN}[OK]${NC}   $line"
  done
fi

echo
echo -e "${BOLD}=================================================================${NC}"
if [ "$VULN_COUNT" -gt 0 ]; then
  echo -e "${RED}RESULT: $VULN_COUNT vulnerable PHP target(s) found. Patch immediately.${NC}"
  echo
  echo "Fixed versions: 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35"
  echo
  echo "  Host:       apt install --only-upgrade php<ver>-fpm php<ver>-cli php<ver>-* "
  echo "              && systemctl restart php<ver>-fpm   (use your distro's package manager equivalent)"
  echo "  Docker:     pin/bump the base image to a patched tag, then:"
  echo "              docker compose build --pull --no-cache && docker compose up -d --force-recreate"
  echo "  Kubernetes: update the image tag in the Deployment/StatefulSet spec, then:"
  echo "              kubectl rollout restart deployment/<name> -n <namespace>"
  echo
  echo -e "${YELLOW}Interim mitigation while patching: set session.upload_progress.enabled = 0${NC}"
  echo -e "${YELLOW}in php.ini on every vulnerable target above, then restart it.${NC}"
  echo
  echo "---"
  echo "Scanner by ${AUTHOR} — ${AUTHOR_GITHUB} — ${AUTHOR_CONTACT}"
  exit 1
else
  echo -e "${GREEN}RESULT: No vulnerable PHP versions detected.${NC}"
  echo
  echo "---"
  echo "Scanner by ${AUTHOR} — ${AUTHOR_GITHUB} — ${AUTHOR_CONTACT}"
  exit 0
fi