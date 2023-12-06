REM --------------------------------------------------------
REM MANGED DEPENDENCIES (PICK EITHER MANAGED OR UNLOCKED)  -
REM --------------------------------------------------------
REM Managed package - Lightweight - Apex Unit Test Util v2@2.3.0-1
sf package install --package 04tP30000007oePIAQ -w 30

REM Managed package - Lightweight - REST Util@0.10.0-1
sf package install --package 04tP30000007sN3IAI -w 30


REM --------------------------------------------------------
REM UNLOCKED DEPENDENCIES (PICK EITHER MANAGED OR UNLOCKED)-
REM --------------------------------------------------------
REM Unlocked package - Lightweight - Apex Unit Test Util v2 (Unlocked)@2.3.0-1
sf package install --package 04tP30000007og1IAA -w 30

REM Unlocked package - Lightweight - REST Util (Unlocked)0.10.0-1
sf package install --package 04tP30000007sQHIAY -w 30

REM --------------------------------------------------------
REM                  ASSIGN PERMISSION SETS                -
REM --------------------------------------------------------
sf org assign permset --name "Lightweight_Apex_Unit_Test_Util_v2"
sf org assign permset --name "Lightweight_REST_Util"
sf org assign permset --name "Lightweight_Auth_Provider_Util_Admin"
