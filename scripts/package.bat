rem CREATE A PACKAGE - UPDATE DEVHUB
sf package create --name "Lightweight - Auth Provider Util v2" --description "A lightweight Auth Provider Utility to add support for User Context Mapping and basic (error) logging." --package-type "Managed" --path "force-app" --target-dev-hub "[DEVHUB NAME]"

rem CREATE A PACKAGE VERSION - UPDATE DEVHUB
sf package version create --package "Lightweight - Auth Provider Util v2" --installation-key-bypass --code-coverage --target-dev-hub  "[DEVHUB NAME]" -w 30

rem PROMOTE THE PACKAGE VERSION - UPDATE NAME + DEVHUB
sf package version promote --package "Lightweight - Auth Provider Util@0.3.0-1" --target-dev-hub  "[DEVHUB NAME]"
