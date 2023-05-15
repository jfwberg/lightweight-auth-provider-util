rem CREATE A PACKAGE - UPDATE DEVHUB
sf package create --name "Auth Provider Util" --description "A generic Auth Provider Utility to add support for User Context Mapping and basic (error) logging." --package-type "Managed" --path "force-app" --target-dev-hub "[DEVHUB NAME]"

rem CREATE A PACKAGE VERSION - UPDATE DEVHUB
sf package version create --package "Auth Provider Util" --installation-key-bypass --code-coverage --target-dev-hub  "[DEVHUB NAME]" -w 30

rem PROMOTE THE PACKAGE VERSION - UPDATE NAME + DEVHUB
rem sf package version promote --package "Auth Provider Util@0.1.0-1" --target-dev-hub  "[DEVHUB NAME]"
