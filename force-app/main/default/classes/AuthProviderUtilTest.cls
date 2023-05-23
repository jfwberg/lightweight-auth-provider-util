/**
 * @author      Justus van den Berg (jfwberg@gmail.com)
 * @date        May 2023
 * @copyright   (c) 2023 Justus van den Berg
 * @license     MIT (See LICENSE file in the project root)
 * @description Class containing the Auth Provider Utilities Test Methods
 */
@IsTest
private with sharing class AuthProviderUtilTest {
    
    // User for the running the tests
    private static final User ADMIN_USER = createRunAsUser('Auth_Provider_Util_Admin');
    private static final User END_USER   = createRunAsUser('Auth_Provider_Util_User');

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
    static void testUtilitiesWithoutMapping(){
        Test.startTest();
        System.runAs(ADMIN_USER){
            // Method to insert an (error) log. Can be used for a success as well, but that should be checked in the external system
            AuthProviderUtil.insertLog(
                authProviderName,
                userId,
                logId,
                message
            );

            // Update the mapping details on the user mapping record
            AuthProviderUtil.updateMappingLoginDetails(
                authProviderName,
                userId
            );
        }
        Test.stopTest();

        // Assert the new log is inserted
        System.assertEquals(
            1,
            [SELECT COUNT() FROM Auth_Provider_Log__c],
            'Expected a single log record'
        );
    }


    /**
     * @description Method to test inserting a log without with an existing mapping record
     *              - Creates a log and links the related mapping record to that log
     *              - Updates the mapping record to simulate a succesful login (token request)
     */
    @IsTest
    static void testUtilitiesWithMapping(){
        
        Test.startTest();
        System.runAs(ADMIN_USER){
            // Create a new user mapping record
            Auth_Provider_User_Mapping__c userMapping = new Auth_Provider_User_Mapping__c(
                Auth_Provider_Name__c = authProviderName,
                User__c = userId,
                Target_User_Identifier__c = targetUserId
            );
            insert userMapping;

            // Test the get subject method
            System.assertEquals(
                targetUserId,
                AuthProviderUtil.getSubjectFromUserMapping(authProviderName, userId),
                'Unexpected target user identifier received'
            );

            // Method to insert an (error) log. Can be used for a success as well, but that should be checked in the external system
            AuthProviderUtil.insertLog(
                authProviderName,
                userId,
                logId,
                message
            );
            
            // Force the platform events to be delivered
            Test.getEventBus().deliver();

            // Query the user mapping, this will fail if there is no user mapping logged
            userMapping = [ SELECT Id, Last_Auth_Provider_Log__c, Last_Login_Date__c, Number_of_Logins__c
                            FROM Auth_Provider_User_Mapping__c WHERE Last_Auth_Provider_Log__c != null LIMIT 1
                        ];

            // Validate expected updates on the mapping record
            System.assertEquals(true, userMapping.Last_Auth_Provider_Log__c != null,'Expected no auth provider log');
            System.assertEquals(true, userMapping.Last_Login_Date__c        == null,'Expected no last login date to be populated');
            System.assertEquals(true, userMapping.Number_of_Logins__c       == 0,   'Expected number of logins to be 0');
            
            // Update the mapping details on the user mapping record
            AuthProviderUtil.updateMappingLoginDetails(
                authProviderName,
                userId
            );
        }
        Test.stopTest();

        // Query the user mapping again now the login details have been updated
        Auth_Provider_User_Mapping__c userMapping = [   SELECT Id, Last_Auth_Provider_Log__c, Last_Login_Date__c, Number_of_Logins__c
                                                        FROM Auth_Provider_User_Mapping__c WHERE Last_Auth_Provider_Log__c != null LIMIT 1
        ];

        // Validate expected updates on the mapping record
        System.assertEquals(true , userMapping.Last_Login_Date__c    != null, 'Expected a last login date to be populated');
        System.assertEquals(true , userMapping.Number_of_Logins__c   == 1,    'Expected number of logins to be 1');
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
            // Validate the exception message
            System.assertEquals(
                String.format(
                    AuthProviderUtil.INVALID_AUTH_PROVIDER_MSG,
                    new String[]{'randomValueHereXYZ'}
                ),
                e.getMessage(),
                'Unexpected validation message'
            );
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
                AuthProviderUtil.insertLog(null,null,null,null);
            }catch(Exception e){
                // Validate the exception message
                System.assertEquals(
                    AuthProviderUtil.LOG_INPUT_VALIDATION_MSG,
                    e.getMessage(),
                    'Unexpected validation message'
                );
            }
        }
        Test.stopTest();
    }


    /**
     * @description Method that tests all global methods from the callable function again.
     *              This method also tests that all logic runs under user context
     */
    @IsTest
    static void testCallable(){
        Test.startTest();
        
        // Insert the mapping as an admin (what we expect is normal)
        System.runAs(ADMIN_USER){
            // Create a new user mapping record
            Auth_Provider_User_Mapping__c userMapping = new Auth_Provider_User_Mapping__c(
                Auth_Provider_Name__c = authProviderName,
                User__c = userId,
                Target_User_Identifier__c = targetUserId
            );
            insert userMapping;

            // Validate the owner has changed accordingly
            System.assertEquals(
                END_USER.Id,
                [SELECT OwnerId FROM Auth_Provider_User_Mapping__c WHERE Id = :userMapping.Id LIMIT 1].OwnerId,
                'Unexpected OwnerId'
            );

            // Validate the owner has changed accordingly
            System.assertEquals(
                authProviderName + '_' + userId,
                [SELECT Auth_Provider_User_Id_Validation__c FROM Auth_Provider_User_Mapping__c WHERE Id = :userMapping.Id LIMIT 1].Auth_Provider_User_Id_Validation__c,
                'Unexpected validation field value'
            );
        }

        // Run the full test again but this time as an end user with a different permission set
        System.runAs(END_USER){
            
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
            System.assertEquals(null, insertLogResult,'Expected a void to return null');


            // Test checkUserMappingExistsResult
            Boolean checkUserMappingExistsResult;
            checkUserMappingExistsResult = (Boolean) extension.call('checkUserMappingExists', new Map<String, Object> { 
                'authProviderName' => authProviderName,
                'userId'           => userId
            });
            System.assertEquals(true, checkUserMappingExistsResult,'Expected the user mapping to exist');


            // Test updateMappingLoginDetails
            Object updateMappingLoginDetailsResult;
            updateMappingLoginDetailsResult = extension.call('updateMappingLoginDetails', new Map<String, Object> { 
                'authProviderName' => authProviderName,
                'userId'           => userId
            });
            System.assertEquals(null, updateMappingLoginDetailsResult,'Expected the a void to return null');
            

            // Test getSubjectFromUserMapping
            String getSubjectFromUserMappingResult;
            getSubjectFromUserMappingResult = (String) extension.call('getSubjectFromUserMapping', new Map<String, Object> { 
                'authProviderName' => authProviderName,
                'userId'           => userId
            });
            System.assertEquals(targetUserId, getSubjectFromUserMappingResult,'Unexpected target Id');


            // Test the exception
            try{
                extension.call('invalid method',null);
                throw new StringException('This part should not be reached');
            }catch(AuthProviderUtil.AuthProviderUtilException e){
                System.assertEquals(
                    AuthProviderUtil.INVALID_METHOD_CALLED_MSG,
                    e.getMessage(),
                    'Unexpected Exception message'
                );
            }

        }
        Test.stopTest();
    }


    /**
     * @description Method to create a run as user with a permission set
     * @param       permissionSetName The (api) name of the Permission Set
     * @return      A User record that can be used with the runAs() function
     */
    private static User createRunAsUser(String permissionSetName){

        // Create a new user
        User runAsUser = new User();

        // Query profile Id
        String profileId = [SELECT Id FROM Profile WHERE Name = 'Minimum Access - Salesforce' WITH SECURITY_ENFORCED LIMIT 1]?.Id;

        // Create a random username
        String username = EncodingUtil.convertToHex(Crypto.generateAESKey(128)) + '@' + EncodingUtil.convertToHex(Crypto.generateAESKey(128)) +'.com.invalid';
    
        // Setup a user, so you can run the test code for a specific profile / permission set
        runAsUser.Alias             = userName.subString(0,8);
        runAsUser.UserName          = userName;
        runAsUser.Email             = userName;
        runAsUser.FirstName         = 'Apex Test';
        runAsUser.LastName          = 'Temporary User';
        runAsUser.EmailEncodingKey  = 'UTF-8';
        runAsUser.LanguageLocaleKey = 'en_US';
        runAsUser.LocaleSidKey      = 'en_US';
        runAsUser.TimeZoneSidKey    = 'Europe/London';
        runAsUser.ProfileId         = profileId;
        runAsUser.IsActive          = true;
        
        // Insert the user
        insert runAsUser;
        
        // Create a permission set
        if(String.isNotBlank(permissionSetName)){
            // Query permission sets and, if permission set value equals null do not query but just get a new list
            PermissionSet permissionSet = [SELECT Id FROM PermissionSet WHERE Name = :permissionSetName WITH SECURITY_ENFORCED LIMIT 1 ];

            // Create the permission set Id
            insert new PermissionSetAssignment(
                AssigneeId      = runAsUser.Id,
                PermissionSetId = permissionSet.Id
            );
        }
        
        // Return the new user
        return runAsUser;
    }
}