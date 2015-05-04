#!/bin/bash
set -euo pipefail
IFS=$'\n\t'

ambuild
(cd package/addons/sourcemod/scripting/ && ../../../../../../../sourcemod/spcomp -iinclude webcon.sp)
mv package/addons/sourcemod/scripting/webcon.smx ../../../tf2/tf/addons/sourcemod/plugins/
rsync -ahW package/addons/ ../../../tf2/tf/addons/
