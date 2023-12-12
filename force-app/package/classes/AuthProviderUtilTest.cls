/**
 * @author      Justus van den Berg (jfwberg@gmail.com)
 * @date        May 2023
 * @copyright   (c) 2023 Justus van den Berg
 * @license     MIT (See LICENSE file in the project root)
 * @description Class containing the Auth Provider Utilities Test Methods
 * @note        Suppress assert warnings as assert is done in a utility, so false-positive
 */
@IsTest
@SuppressWarnings('PMD.ApexUnitTestClassShouldHaveAsserts')
private with sharing class AuthProviderUtilTest {
    
    // User for the running the tests
    private static final User END_USER   = utl.Tst.createRunAsUser(utl.Tst.MINIMUM_ACCESS_PROFILE, 'Lightweight_Auth_Provider_Util');
    private static final User ADMIN_USER = utl.Tst.createRunAsUser(utl.Tst.MINIMUM_ACCESS_PROFILE, 'Lightweight_Auth_Provider_Util');

    // Test data values
    private static String authProviderName = 'myAuthProvider';
    private static String userId           = END_USER.Id;
    private static String targetUserId     = ADMIN_USER.Id;
    private static String logId            = EncodingUtil.convertToHex(Crypto.generateAESKey(128));
    private static String message          = '(Error) Message content';


    /**
     * @description Method to test inserting a log without an existing mapping record
     */
    @IsTest
    static void testInsertLog(){
        
        // Log to assert
        Integer logCount;
        Auth_Provider_Log__c log; 
        Auth_Provider_Log__c logRelatedToMapping; 
        Auth_Provider_User_Mapping__c userMapping;
        
        // Run the test
        Test.startTest();
        System.runAs(ADMIN_USER){
            
            // Create a log without a user mapping
            AuthProviderUtil.insertLog(
                authProviderName,
                userId,
                logId,
                message
            );

            // Force delivery
            Test.getEventBus().deliver();

            // Create a log with user mapping
            userMapping = new Auth_Provider_User_Mapping__c(
                Auth_Provider_Name__c = authProviderName,
                User__c = userId,
                Target_User_Identifier__c = targetUserId
            );
            insert userMapping;

            // Create a log without a user mapping
            AuthProviderUtil.insertLog(
                authProviderName,
                userId,
                logId.reverse(),
                message
            );

            // Force delivery
            Test.getEventBus().deliver();
             
            // Note the log count
            logCount = [SELECT COUNT() FROM Auth_Provider_Log__c];

            // Query our (if all good) new log
            log = [ SELECT Auth_Provider_Name__c, User__c, Log_Id__c, Message__c 
                    FROM  Auth_Provider_Log__c 
                    WHERE Log_Id__c = :logId LIMIT 1
            ];

            // Query our (if all good) new log
            logRelatedToMapping = [ SELECT Auth_Provider_Name__c, User__c, Log_Id__c, Message__c 
                    FROM  Auth_Provider_Log__c 
                    WHERE Log_Id__c = :logId.reverse() LIMIT 1
            ];

            // Requery the user mapping
            userMapping = [ SELECT Last_Auth_Provider_Log__c FROM Auth_Provider_User_Mapping__c 
                            WHERE Id = :userMapping.Id LIMIT 1];
        }
        Test.stopTest();

        // There should be a single log inserted
        Assert.areEqual(2, logCount, 'Unexpected Record count');

        // Assert the log values
        Assert.areEqual(authProviderName, log.Auth_Provider_Name__c, 'Unexpected field value');
        Assert.areEqual(userId,           log.User__c,               'Unexpected field value');
        Assert.areEqual(logId,            log.Log_Id__c,             'Unexpected field value');
        Assert.areEqual(message,          log.Message__c,            'Unexpected field value');

        // Validate expected updates on the mapping record
        Assert.areEqual(
            logRelatedToMapping.Id,
            userMapping.Last_Auth_Provider_Log__c,
            'Unexpected field value'
        );
    }


    /**
     * @description Method to test the updating of a user mapping
     */
    @IsTest
    static void testUpdateMappingLoginDetails(){
        
        // Subject to validate
        String subject;

        // Create a new user mapping record
        Auth_Provider_User_Mapping__c userMapping;

        // Run the test
        Test.startTest();
        System.runAs(ADMIN_USER){
            // Create test data mapping
            userMapping = new Auth_Provider_User_Mapping__c(
                Auth_Provider_Name__c = authProviderName,
                User__c = userId,
                Target_User_Identifier__c = targetUserId
            );
            insert userMapping;
            
            // Update the mapping details on the user mapping record
            AuthProviderUtil.updateMappingLoginDetails(
                authProviderName,
                userId
            );

            // Run the details for coverage in case the auth provider does not exist
            AuthProviderUtil.updateMappingLoginDetails(
                'Invalid',
                UserInfo.getUserId()
            );

            // Force delivery
            Test.getEventBus().deliver();

            // Requery the user mapping
            userMapping = [ SELECT Last_Login_Date__c, Number_of_Logins__c FROM Auth_Provider_User_Mapping__c 
                            WHERE Auth_Provider_Name__c = :authProviderName AND User__c = :userId LIMIT 1];

            // Assign the subject
            subject = AuthProviderUtil.getSubjectFromUserMapping(authProviderName, userId);
        }
        Test.stopTest();

        // Validate the record has been updated
        Assert.isNotNull(userMapping.Last_Login_Date__c,  'Unexpected field value');
        Assert.isNotNull(userMapping.Number_of_Logins__c, 'Unexpected field value');
    
        // Test the get subject method
        Assert.areEqual(
            targetUserId,
            subject,
            'Unexpected target user identifier received'
        );
    }


    /**
     * @description Method to test the inserting of history records
     */
    @IsTest
    static void testInsertLoginHistoryRecord(){
       
        // Run the test
        Test.startTest();
        System.runAs(ADMIN_USER){

            // Overload method to insert a login history record
            AuthProviderUtil.insertLoginHistoryRecord(
                authProviderName,
                userId,
                'Refresh',
                Datetime.now()
            );
            
            // Main method to insert a login history record
            AuthProviderUtil.insertLoginHistoryRecord(
                authProviderName,
                userId,
                'Refresh',
                Datetime.now(),
                true,
                'Data Cloud',
                'Additional info'
            );
        }
        Test.stopTest();

        // Assert the new logs are both inserted
        Assert.areEqual(
            2,
            [SELECT COUNT() FROM Auth_Provider_Login_History__c],
            'Expecting 2 login history records'
        );
    }


    /**
     * @description Method to get the user id and the session data from cookies
     */
    @SuppressWarnings('PMD.AvoidHardcodingId')
    @IsTest
    static void testGetAuthUserDataFromCookieHeader(){
        
        // Data to validate
        Auth.UserData data;

        // Execute the test
        Test.startTest();
        System.runAs(ADMIN_USER){
            // Create the mock response
            utl.Mck.setResponse('{"active": true, "email": "henk@devries.nl", "email_verified": true, "family_name": "de Vries", "given_name": "Henk", "is_app_installed": true, "is_salesforce_integration_user": false, "locale": "en_GB", "name": "Henk de Vries", "preferred_username": "henk@devries.nl", "profile": "#", "user_id": "0058d0000050rYpAAI", "user_type": "STANDARD", "utcOffset": 0, "zoneinfo": "Europe/London"}');
            
            // Execute logic
            data = AuthProviderUtil.getAuthUserDataFromCookieHeader('BrowserId=JrIF-JNyEe6Z1ZuCfDCB4w; BrowserId_sec=JrIF-JNyEe6Z1ZuCfDCB4w; sfdcConsent=1; CookieConsentPolicy=0:1; LSKey-c$CookieConsentPolicy=0:1; webact=%7B%22l_vdays%22%3A-1%2C%22l_visit%22%3A0%2C%22session%22%3A1701782904312%2C%22l_search%22%3A%22%22%2C%22l_dtype%22%3A%22SFDC%20Network%22%2C%22l_page%22%3A%22SFDC%3Aus%3Alogin%22%2C%22l_page_url%22%3A%22https%3A%2F%2Fc.salesforce.com%2Flogin-messages%2Fpromos.html%22%2C%22counter%22%3A0%2C%22pv%22%3A2%2C%22f_visit%22%3A1701782898284%2C%22seg%22%3A%22non-customer%3Aus%22%2C%22d%22%3A%2270130000000sUW0%22%7D; OptanonConsent=isGpcEnabled=0&datestamp=Tue+Dec+05+2023+13%3A28%3A24+GMT%2B0000+(Greenwich+Mean+Time)&version=202306.1.0&browserGpcFlag=0&isIABGlobal=false&hosts=&consentId=924e06fd-9173-487d-983d-601ba5903d80&interactionCount=1&landingPath=https%3A%2F%2Fc.salesforce.com%2Flogin-messages%2Fpromos.html&groups=1%3A1%2C3%3A0%2C2%3A0%2C4%3A0; inst=APP_Pv; rememberUn=false; com.salesforce.LocaleInfo=uk; oinfo=c3RhdHVzPVRSSUFMJnR5cGU9MyZvaWQ9MDBEUHYwMDAwMDBmdVhp; sfdc_lv2=KxG83HXUehD4n5M2wLsGr31CR3XUwK0AXt7PTdZyIRS6VZfF6pOuJeV85OdArj90o=; disco=Pv:00DPv000000fuXi:005Pv000001MB5t:6; autocomplete=1; sid=00DPv000000fuXi!AQEAQNVd17egCdH_NB.Qcwvk5ZG9EP8cZONDxXDNCDi3Mczbneaya8hCxWLGnaxJU8GUV3omNAW2Wj1T26j47sMFRROJcWUm; sid_Client=v000001MB5tv000000fuXi; clientSrc=81.157.92.38; oid=00DPv000000fuXi; 79eb100099b9a8bf=3:false:.salesforce.com; idccsrf=382450550027570323317017829629063455687590152459083');
        }
        Test.stopTest();

        // Assert the user Id
        Assert.areEqual('0058d0000050rYpAAI', data.identifier, 'Unexpected UserId');
    }


    /**
     * @description Method to test the auth provider name validation logic
     */
    @IsTest
    static void testAuthProviderNameValidation(){
        
        try{
            // Don't ignore the validation in a test
            AuthProviderUtil.ignoreValidationInTest = false;

            // Run validation
            AuthProviderUtil.validateAuthProviderName(
                Auth_Provider_Log__c.Auth_Provider_Name__c,    
                new SObject[]{new Auth_Provider_Log__c(Auth_Provider_Name__c = 'randomValueHereXYZ')}
            );
        }catch(Exception e){
            // Validate Exception message
            utl.Tst.assertExceptionMessage(AuthProviderUtil.LOG_INPUT_VALIDATION_MSG, 'randomValueHereXYZ', e);
        }
    }



    /**
     * @description Method to test the log input validation logic
     */
    @IsTest
    static void testValidateLogInput(){
        Test.startTest();
        System.runAs(ADMIN_USER){
            try{
                // Should throw an error
                AuthProviderUtil.insertLog(null,null,null,null);

                // This method will fail the test as it should not be reached
                utl.Tst.assertExceptionHasBeenThrow();

            }catch(Exception e){
                // Validate Exception message
                utl.Tst.assertExceptionMessage(AuthProviderUtil.LOG_INPUT_VALIDATION_MSG, e);
            }
        }
        Test.stopTest();
    }


    /**
     * @description Method that tests all global methods from the callable function again.
     *              This method also tests that all logic runs under user context
     */
    @IsTest
    @SuppressWarnings('PMD.AvoidHardcodingId')
    static void testCallable(){
        
        Test.startTest();
        
        // Run the full test again but this time as an end user with a different permission set
        System.runAs(END_USER){
            
            // Create test data mapping
            Auth_Provider_User_Mapping__c userMapping = new Auth_Provider_User_Mapping__c(
                Auth_Provider_Name__c = authProviderName,
                User__c = userId,
                Target_User_Identifier__c = targetUserId
            );
            insert userMapping;

            // Dymically instanciate class
            Callable extension = (Callable) Type.forName(String.valueOf(AuthProviderUtil.class)).newInstance();

            // Test insertLog
            Object insertLogResult;
            insertLogResult = extension.call('insertLog', new Map<String, Object> { 
                'authProviderName' => authProviderName,
                'userId'           => userId,
                'logId'            => logId,
                'message'          => message
            });
            Assert.areEqual(null, insertLogResult,'Expected a void to return null');

            // Test insertLog
            Object insertLoginHistoryRecordResult;
            insertLoginHistoryRecordResult = extension.call('insertLoginHistoryRecord', new Map<String, Object> { 
                'authProviderName' => authProviderName,
                'userId'           => userId,
                'flowType'         => 'Refresh',
                'timestamp'        => Datetime.now(),
                'success'          => true, // or false
                'providerType'     => 'Data Cloud',
                'loginInfo'        => 'Optional debug info or login error info'
            });
            Assert.areEqual(null, insertLoginHistoryRecordResult,'Expected a void to return null but not give any errors');

            // Test insertLog with null values for the overload
            insertLoginHistoryRecordResult = extension.call('insertLoginHistoryRecord', new Map<String, Object> { 
                'authProviderName' => authProviderName,
                'userId'           => userId,
                'flowType'         => 'Refresh',
                'timestamp'        => Datetime.now()
            });
            Assert.areEqual(null, insertLoginHistoryRecordResult,'Expected a void to return null but not give any errors');

            // Test checkUserMappingExistsResult
            Boolean checkUserMappingExistsResult;
            checkUserMappingExistsResult = (Boolean) extension.call('checkUserMappingExists', new Map<String, Object> { 
                'authProviderName' => authProviderName,
                'userId'           => userId
            });
            Assert.areEqual(true, checkUserMappingExistsResult,'Expected the user mapping to exist');


            // Test updateMappingLoginDetails
            Object updateMappingLoginDetailsResult;
            updateMappingLoginDetailsResult = extension.call('updateMappingLoginDetails', new Map<String, Object> { 
                'authProviderName' => authProviderName,
                'userId'           => userId
            });
            Assert.areEqual(null, updateMappingLoginDetailsResult,'Expected the a void to return null');
            

            // Test getSubjectFromUserMapping
            String getSubjectFromUserMappingResult;
            getSubjectFromUserMappingResult = (String) extension.call('getSubjectFromUserMapping', new Map<String, Object> { 
                'authProviderName' => authProviderName,
                'userId'           => userId
            });
            Assert.areEqual(targetUserId, getSubjectFromUserMappingResult,'Unexpected target Id');

            // Create the mock response
            utl.Mck.setResponse('{"active": true, "email": "henk@devries.nl", "email_verified": true, "family_name": "de Vries", "given_name": "Henk", "is_app_installed": true, "is_salesforce_integration_user": false, "locale": "en_GB", "name": "Henk de Vries", "preferred_username": "henk@devries.nl", "profile": "#", "user_id": "0058d0000050rYpAAI", "user_type": "STANDARD", "utcOffset": 0, "zoneinfo": "Europe/London"}');
            
            // Test getAuthUserDataFromCookieHeader
            Auth.UserData getAuthUserDataFromCookieHeaderResult;
            getAuthUserDataFromCookieHeaderResult = (Auth.UserData) extension.call('getAuthUserDataFromCookieHeader', new Map<String, Object> { 
                'cookieHeader' => 'BrowserId=JrIF-JNyEe6Z1ZuCfDCB4w; BrowserId_sec=JrIF-JNyEe6Z1ZuCfDCB4w; sfdcConsent=1; CookieConsentPolicy=0:1; LSKey-c$CookieConsentPolicy=0:1; webact=%7B%22l_vdays%22%3A-1%2C%22l_visit%22%3A0%2C%22session%22%3A1701782904312%2C%22l_search%22%3A%22%22%2C%22l_dtype%22%3A%22SFDC%20Network%22%2C%22l_page%22%3A%22SFDC%3Aus%3Alogin%22%2C%22l_page_url%22%3A%22https%3A%2F%2Fc.salesforce.com%2Flogin-messages%2Fpromos.html%22%2C%22counter%22%3A0%2C%22pv%22%3A2%2C%22f_visit%22%3A1701782898284%2C%22seg%22%3A%22non-customer%3Aus%22%2C%22d%22%3A%2270130000000sUW0%22%7D; OptanonConsent=isGpcEnabled=0&datestamp=Tue+Dec+05+2023+13%3A28%3A24+GMT%2B0000+(Greenwich+Mean+Time)&version=202306.1.0&browserGpcFlag=0&isIABGlobal=false&hosts=&consentId=924e06fd-9173-487d-983d-601ba5903d80&interactionCount=1&landingPath=https%3A%2F%2Fc.salesforce.com%2Flogin-messages%2Fpromos.html&groups=1%3A1%2C3%3A0%2C2%3A0%2C4%3A0; inst=APP_Pv; rememberUn=false; com.salesforce.LocaleInfo=uk; oinfo=c3RhdHVzPVRSSUFMJnR5cGU9MyZvaWQ9MDBEUHYwMDAwMDBmdVhp; sfdc_lv2=KxG83HXUehD4n5M2wLsGr31CR3XUwK0AXt7PTdZyIRS6VZfF6pOuJeV85OdArj90o=; disco=Pv:00DPv000000fuXi:005Pv000001MB5t:6; autocomplete=1; sid=00DPv000000fuXi!AQEAQNVd17egCdH_NB.Qcwvk5ZG9EP8cZONDxXDNCDi3Mczbneaya8hCxWLGnaxJU8GUV3omNAW2Wj1T26j47sMFRROJcWUm; sid_Client=v000001MB5tv000000fuXi; clientSrc=81.157.92.38; oid=00DPv000000fuXi; 79eb100099b9a8bf=3:false:.salesforce.com; idccsrf=382450550027570323317017829629063455687590152459083'
            });

            // Assert the user Id
            Assert.areEqual('0058d0000050rYpAAI', getAuthUserDataFromCookieHeaderResult.identifier, 'Unexpected UserId');

            try{
                // Test the exception
                extension.call('invalid method',null);
                
                // This method will fail the test as it should not be reached
                utl.Tst.assertExceptionHasBeenThrow();

            }catch(AuthProviderUtil.AuthProviderUtilException e){
                // Validate Exception message
                utl.Tst.assertExceptionMessage(AuthProviderUtil.INVALID_METHOD_CALLED_MSG, e);
            }
        }
        
        Test.stopTest();
    }
    
}