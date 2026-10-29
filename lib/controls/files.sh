# shellcheck shell=bash
#
# files.sh - account file permission controls (FILE-*).
#
# Part of HLinux (harden-audit.sh). Sourced, not executed.

# ---------------------------------------------------------------------------
# 5. Permissions on account files
# ---------------------------------------------------------------------------

register_control FILE-1 high "File permissions" fix_file_perms \
    "/etc/passwd has safe permissions" \
    "If anyone but root can write /etc/passwd, they can add a UID 0 account or change another user's shell - instant root."
register_control FILE-2 high "File permissions" fix_file_perms \
    "/etc/shadow has safe permissions" \
    "/etc/shadow holds every password hash. If ordinary users can read it, they can crack the hashes offline at their leisure."
register_control FILE-3 medium "File permissions" fix_file_perms \
    "/etc/group has safe permissions" \
    "Write access to /etc/group lets a user add themselves to sudo, wheel or docker - a direct path to root."
register_control FILE-4 medium "File permissions" fix_file_perms \
    "/etc/gshadow has safe permissions" \
    "/etc/gshadow holds group password hashes and group administrator lists; it should be as protected as /etc/shadow."

# check_file_perms ID PATH MAX_MODE OWNER ALLOWED_GROUPS FIX_GROUP FIX_MODE WHY
check_file_perms() {
    local id=$1 path=$2 max=$3 owner=$4 groups=$5 fix_group=$6 fix_mode=$7 why=$8
    local title="$path permissions are $max or stricter, owned by $owner:${groups// //}"
    local st mode f_owner f_group problems=()
    if [[ ! -e $path ]]; then
        report SKIP "$id" "$title" "$path does not exist on this system." ""
        return
    fi
    st=$(stat -Lc '%a %U %G' "$path" 2>/dev/null) || {
        report SKIP "$id" "$title" "Could not stat $path." "Re-run this audit as root (sudo)."
        return
    }
    read -r mode f_owner f_group < <(printf '%s\n' "$st")
    if (( (8#$mode) & ~(8#$max) )); then
        problems+=("mode is $mode, which grants more than $max")
    fi
    [[ $f_owner == "$owner" ]] || problems+=("owner is '$f_owner', expected '$owner'")
    [[ " $groups " == *" $f_group "* ]] || problems+=("group is '$f_group', expected '${groups// /\' or \'}'")
    if ((${#problems[@]} == 0)); then
        report PASS "$id" "$title" "$path is mode $mode, owned by $f_owner:$f_group."
    else
        report FAIL "$id" "$title" "$(join '; ' "${problems[@]}"). $why" \
            "sudo chown $owner:$fix_group $path && sudo chmod $fix_mode $path"
    fi
}

check_file_permissions() {
    section "5. Account file permissions"
    # Debian-style systems use group "shadow" (0640); RHEL-style use root (0000).
    local shadow_group=root shadow_mode=0000
    if getent group shadow >/dev/null 2>&1; then
        shadow_group=shadow shadow_mode=0640
    fi
    check_file_perms FILE-1 /etc/passwd  644 root "root"        root          0644 \
        "Only root should be able to modify the list of accounts."
    check_file_perms FILE-2 /etc/shadow  640 root "root shadow" "$shadow_group" "$shadow_mode" \
        "/etc/shadow contains password hashes; if other users can read it they can crack them offline."
    check_file_perms FILE-3 /etc/group   644 root "root"        root          0644 \
        "Only root should be able to modify group membership (e.g. add someone to sudo/wheel)."
    check_file_perms FILE-4 /etc/gshadow 640 root "root shadow" "$shadow_group" "$shadow_mode" \
        "/etc/gshadow contains group password hashes and administrator lists."
}
