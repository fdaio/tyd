#!/bin/sh
# Decide whether today's main commit should be published.
#
# Version: <YYYY.MM.DD>-<7-char commit> in Asia/Shanghai.
# Publish when HEAD is not already pointed at by a tag of that form.
# A manual tag such as v0.1.0 does not count.
#
# RELEASE_DATE=YYYY.MM.DD overrides the calendar day (tests).
# When GITHUB_OUTPUT is set, the same keys are appended for Actions.
set -eu

day="${RELEASE_DATE:-$(TZ=Asia/Shanghai date +%Y.%m.%d)}"
case "$day" in
	[0-9][0-9][0-9][0-9].[0-9][0-9].[0-9][0-9]) ;;
	*)
		echo "release-plan: bad date $day" >&2
		exit 1
		;;
esac

sha=$(git rev-parse HEAD)
short=$(git rev-parse --short=7 HEAD)
version="${day}-${short}"

publish=true
reason="commits since the last daily release"

already=false
for tag in $(git tag --points-at HEAD); do
	case "$tag" in
		[0-9][0-9][0-9][0-9].[0-9][0-9].[0-9][0-9]-*)
			already=true
			;;
	esac
done

if [ "$already" = true ]; then
	publish=false
	reason="no new commits since the last daily release"
elif git rev-parse -q --verify "refs/tags/${version}" >/dev/null 2>&1; then
	publish=false
	reason="tag ${version} already exists"
fi

emit() {
	printf '%s\n' "publish=${publish}" "version=${version}" "sha=${sha}" "reason=${reason}"
}

emit
if [ -n "${GITHUB_OUTPUT:-}" ]; then
	emit >>"$GITHUB_OUTPUT"
fi
