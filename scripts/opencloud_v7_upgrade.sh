#!/bin/bash
###############################################################################
#  OpenCloud  ->  v7.0.0+  Upgrade Helper   (Unraid / Docker, NOT compose)
###############################################################################
#
#  WHAT THIS FIXES
#  ---------------
#  After updating the OpenCloud image to v7.0.0 (or later) the container can
#  get stuck in a crash loop with:
#
#      "The service account id has not been configured for sharing."
#
#  v7.0.0 made the "sharing" service require its own service-account config.
#  Installs created before v7 have an opencloud.yaml whose `sharing:` block is
#  missing the `service_account:` sub-block that every other service already
#  has. This script adds it, reusing the SAME id/secret the other services use
#  (it must match - never invent a new one).
#
#  WHAT IT DOES
#  ------------
#    1. Stops the OpenCloud container
#    2. Detects/aside-moves a duplicate opencloud.yaml (a classic trap)
#    3. Backs up opencloud.yaml
#    4. Adds  sharing.service_account  if (and only if) it is missing,
#       reusing the existing service-account id + secret from the file
#    5. Restarts the container
#
#  SAFE: makes a timestamped backup, is idempotent (re-running does nothing
#  once patched), and never edits anything in DRY_RUN mode.
#
#  NOTE: A fresh v7 install does NOT need this - `opencloud init` generates a
#  complete config on first run. This script is only for EXISTING installs
#  upgrading from v6.x or earlier.
#
#  Tested on Unraid 7.x with the OpenCloud (opencloudeu/opencloud-rolling) image.
###############################################################################
#name=OpenCloud v7 Upgrade Fix
#description=Adds the v7.0.0 sharing service account to an existing opencloud.yaml
#arrayStarted=true

###############################################################################
#  USER CONFIGURATION  -  edit these to match your setup
###############################################################################

# Exact container name as shown on the Unraid Docker tab
OPENCLOUD_CONTAINER="OpenCloud"

# Host path mounted into the container as /etc/opencloud
OCL_CONFIG="/mnt/user/appdata/opencloud/config"

# Parent of the config dir (used only to catch a stray duplicate yaml)
OCL_BASE="/mnt/user/appdata/opencloud"

# true  = show what WOULD happen, change nothing  (run this first!)
# false = actually apply the fix
DRY_RUN="true"

# Start the container again after patching? (ignored when DRY_RUN=true)
RESTART_AFTER="true"

###############################################################################
#  DO NOT EDIT BELOW THIS LINE
###############################################################################

YAML="${OCL_CONFIG}/opencloud.yaml"
STRAY_YAML="${OCL_BASE}/opencloud.yaml"
TS="$(date +%Y%m%d-%H%M%S)"

say()  { echo "$@"; }
line() { echo "------------------------------------------------------------"; }

say "============================================================"
say " OpenCloud v7 Upgrade Fix"
say "============================================================"
say "  Container : ${OPENCLOUD_CONTAINER}"
say "  Config    : ${YAML}"
if [ "${DRY_RUN}" = "true" ]; then
  say "  Mode      : DRY RUN (no changes will be made)"
else
  say "  Mode      : LIVE (changes will be applied)"
fi
say "============================================================"
say ""

# ---- Pre-flight ------------------------------------------------------------
if ! command -v docker >/dev/null 2>&1; then
  say "ERROR: 'docker' not found. Run this on the Unraid host."; exit 1
fi
if ! docker inspect "${OPENCLOUD_CONTAINER}" >/dev/null 2>&1; then
  say "ERROR: container '${OPENCLOUD_CONTAINER}' not found."
  say "       Fix OPENCLOUD_CONTAINER to match the Unraid Docker tab."; exit 1
fi

# ---- Locate config & report duplicates ------------------------------------
say "[1] Checking config files..."
MATCHES="$(find "${OCL_BASE}" -name "opencloud.yaml" 2>/dev/null)"
COUNT="$(printf '%s\n' "${MATCHES}" | grep -c . )"
say "    opencloud.yaml found (${COUNT}):"
printf '%s\n' "${MATCHES}" | sed 's/^/      /'

if [ ! -f "${YAML}" ]; then
  say ""
  say "ERROR: ${YAML} does not exist."
  say "       Your container's config mount may point elsewhere:"
  docker inspect "${OPENCLOUD_CONTAINER}" \
    --format '{{range .Mounts}}{{.Source}} -> {{.Destination}}{{println}}{{end}}' \
    2>/dev/null | grep -i "etc/opencloud" | sed 's/^/         /'
  say "       Set OCL_CONFIG to the host path shown above (the /etc/opencloud source)."
  exit 1
fi

STRAY="no"
if [ -f "${STRAY_YAML}" ] && [ "${OCL_BASE}" != "${OCL_CONFIG}" ]; then
  STRAY="yes"
  say ""
  say "    WARNING: a stray opencloud.yaml exists at the base path:"
  say "      ${STRAY_YAML}"
  say "    The container reads the one under /etc/opencloud, so this stray copy"
  say "    can silently shadow your edits. It will be moved aside."
fi
say ""

# ---- Read existing service account ----------------------------------------
say "[2] Reading the existing service account from opencloud.yaml..."
SA_ID="$(grep -E "^[[:space:]]+service_account_id:" "${YAML}" | head -1 | sed -E 's/^[[:space:]]+service_account_id:[[:space:]]*//')"
SA_SECRET="$(grep -E "^[[:space:]]+service_account_secret:" "${YAML}" | head -1 | sed -E 's/^[[:space:]]+service_account_secret:[[:space:]]*//')"

if [ -z "${SA_ID}" ] || [ -z "${SA_SECRET}" ]; then
  say "ERROR: could not find an existing service_account_id/secret in the file."
  say "       Aborting so nothing is guessed. (No changes made.)"
  exit 1
fi
say "    id     : ${SA_ID}"
say "    secret : ${SA_SECRET}"
say ""

# ---- Decide what the sharing block needs ----------------------------------
say "[3] Inspecting the sharing block..."
HAS_SA="$(awk '/^[a-zA-Z_]/{in_sh=($0~/^sharing:/)?1:0} in_sh&&/^[[:space:]]+service_account:/{print "yes";exit}' "${YAML}")"
HAS_SHARING="$(grep -cE "^sharing:" "${YAML}")"

ACTION="none"
if [ "${HAS_SA}" = "yes" ]; then
  ACTION="skip"
  say "    sharing.service_account is already present -> nothing to do."
elif [ "${HAS_SHARING}" -ge 1 ]; then
  ACTION="insert"
  say "    sharing: exists but has NO service_account -> will insert it."
else
  ACTION="append"
  say "    no sharing: block at all -> will append a new one."
fi
say ""

# ---- DRY RUN stops here ----------------------------------------------------
if [ "${DRY_RUN}" = "true" ]; then
  line
  say " DRY RUN SUMMARY (no changes were made)"
  line
  say "  Stray duplicate yaml to move aside : ${STRAY}"
  say "  Planned action on sharing block    : ${ACTION}"
  if [ "${ACTION}" != "skip" ]; then
    say ""
    say "  It would add this under 'sharing:' :"
    say "      service_account:"
    say "        service_account_id: ${SA_ID}"
    say "        service_account_secret: ${SA_SECRET}"
  fi
  say ""
  say "  When the above looks right, set  DRY_RUN=\"false\"  and run again."
  say ""
  exit 0
fi

# ---- LIVE: stop container --------------------------------------------------
say "[4] Stopping container..."
docker stop "${OPENCLOUD_CONTAINER}" >/dev/null 2>&1
say "    stopped."

# ---- LIVE: move stray yaml -------------------------------------------------
if [ "${STRAY}" = "yes" ]; then
  mv "${STRAY_YAML}" "${STRAY_YAML}.bak.${TS}"
  say "    moved stray yaml -> ${STRAY_YAML}.bak.${TS}"
fi

# ---- LIVE: backup ----------------------------------------------------------
cp "${YAML}" "${YAML}.bak.${TS}"
say "    backup -> ${YAML}.bak.${TS}"

# ---- LIVE: patch -----------------------------------------------------------
say "[5] Applying fix (${ACTION})..."
case "${ACTION}" in
  skip) : ;;
  insert)
    awk -v id="${SA_ID}" -v secret="${SA_SECRET}" '
      { print }
      /^sharing:/ && !d {
        print "  service_account:"
        print "    service_account_id: " id
        print "    service_account_secret: " secret
        d=1
      }' "${YAML}" > "${YAML}.tmp" && mv "${YAML}.tmp" "${YAML}"
    ;;
  append)
    {
      echo ""
      echo "sharing:"
      echo "  service_account:"
      echo "    service_account_id: ${SA_ID}"
      echo "    service_account_secret: ${SA_SECRET}"
    } >> "${YAML}"
    ;;
esac

# ---- Verify ----------------------------------------------------------------
VERIFY="$(awk '/^[a-zA-Z_]/{in_sh=($0~/^sharing:/)?1:0} in_sh&&/^[[:space:]]+service_account:/{print "yes";exit}' "${YAML}")"
if [ "${VERIFY}" = "yes" ]; then
  say "    OK - sharing.service_account is now present."
else
  say "    ERROR - patch did not take. Restoring backup."
  cp "${YAML}.bak.${TS}" "${YAML}"
  say "    restored ${YAML} from backup. No restart performed."
  exit 1
fi
say ""
say "    Resulting sharing block:"
awk '/^sharing:/{f=1} /^[a-zA-Z_]/ && !/^sharing:/ && f{f=0} f{print "      "$0}' "${YAML}"
say ""

# ---- Restart ---------------------------------------------------------------
if [ "${RESTART_AFTER}" = "true" ]; then
  say "[6] Starting container..."
  docker start "${OPENCLOUD_CONTAINER}" >/dev/null
  say "    started."
  say ""
  say "    First boot after upgrade runs a one-time share-manager migration."
  say "    Spaces may be briefly unavailable for a few minutes - this is normal."
  say "    Watch it with:  docker logs -f ${OPENCLOUD_CONTAINER}"
else
  say "[6] RESTART_AFTER=false - start the container yourself when ready."
fi

say ""
say "============================================================"
say " Done. Backup: ${YAML}.bak.${TS}"
say "============================================================"
say ""
say " Note: you do NOT need SHARING_SERVICE_ACCOUNT_ID/SECRET env vars in the"
say " Unraid template. The value lives in opencloud.yaml. (Passing the secret"
say " as an env var is also unreliable if it contains \$ * ^ characters, which"
say " Unraid's shell can mangle.)"
say ""
