package scripts

import _ "embed"

// InstallSH is the one-click installer (scripts/install.sh), served by the Control Panel.
//
//go:embed install.sh
var InstallSH []byte
