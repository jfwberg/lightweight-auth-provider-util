REM *****************************
REM        PACKAGE CREATION   
REM *****************************

REM Package Create Config
SET devHub=devHubAlias
SET packageName=Lightweight - Auth Provider Util v2
SET packageDescription=A lightweight Auth Provider Utility to add support for User Context Mapping and basic (error) logging.
SET packageType=Managed
SET packagePath=force-app/package

REM Package Config
SET packageId=0Ho4K0000008OYUSA2
SET packageVersionId=04tP3000000DieLIAS

REM Create package
sf package create --name "%packageName%" --description "%packageDescription%" --package-type "%packageType%" --path "%packagePath%" --target-dev-hub %devHub%

REM Create package version
sf package version create --package "%packageName%"  --target-dev-hub %devHub% --code-coverage --installation-key-bypass --wait 30

REM Delete package
sf package:delete -p %packageId% --target-dev-hub %devHub% --no-prompt

REM Delete package version
sf package:version:delete -p %packageVersionId% --target-dev-hub %devHub% --no-prompt

REM Promote package version
sf package:version:promote -p %packageVersionId% --target-dev-hub %devHub% --no-prompt
