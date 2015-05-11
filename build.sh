#!/bin/bash
set -euo pipefail
IFS=$'\n\t'

ambuild
(cd package/addons/sourcemod/scripting/ && ../../../../../../../sourcemod/spcomp -iinclude webcon.sp)
(cd package/addons/sourcemod/scripting/ && ../../../../../../../sourcemod/spcomp -iinclude webplayerlist.sp)
mv package/addons/sourcemod/scripting/*.smx ../../../tf2/tf/addons/sourcemod/plugins/
rsync -ahW package/addons/ ../../../tf2/tf/addons/
