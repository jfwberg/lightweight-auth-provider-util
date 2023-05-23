/**
 * @author         Justus van den Berg (jfwberg@gmail.com)
 * @date           May 2023
 * @copyright      (c) 2023 Justus van den Berg
 * @license        MIT (See LICENSE file in the project root)
 * @description    Class containing the Auth Proivder Utilities
 * @false-positive PMD.AvoidGlobalModifier This is a utility that is designed to be called from a
 *                                         managed package. It can be used for a user's own custom
 *                                         Implementation, so global is the way to open up this
 *                                         utility for global use.
 */
@SuppressWarnings('PMD.AvoidGlobalModifier')
global with sharing class AuthProviderUtil implements Callable{

    /** **************************************************************************************************** **
     **                                          PRIVATE VARIABLES                                           **
     ** **************************************************************************************************** **/
    // Switch for allowing to test validation logic
    @TestVisible private static Boolean ignoreValidationInTest = true;

    // User mapping variables, used for checking if a mapping exists
    private static Boolean userMappingRetrieved = false;
    private static Auth_Provider_User_Mapping__c userMapping;


    /** **************************************************************************************************** **
     **                                          PRIVATE CONSTANTS                                           **
     ** **************************************************************************************************** **/
    // Describe the log and mapping object
    private static final Schema.DescribeSObjectResult LOG_DESCRIBE_RESULT     = Auth_Provider_Log__c.getSObjectType().getDescribe(SObjectDescribeOptions.DEFERRED);
    private static final Schema.DescribeSObjectResult MAP_DESCRIBE_RESULT     = Auth_Provider_User_Mapping__c.getSObjectType().getDescribe(SObjectDescribeOptions.DEFERRED);
    private static final Schema.DescribeSObjectResult LOG_EVT_DESCRIBE_RESULT = Auth_Provider_Log_Event__e.getSObjectType().getDescribe(SObjectDescribeOptions.DEFERRED);
    private static final Schema.DescribeSObjectResult MAP_EVT_DESCRIBE_RESULT = Auth_Provider_User_Mapping_Event__e.getSObjectType().getDescribe(SObjectDescribeOptions.DEFERRED);

    // Create a list of log fields with describes (these are the createable fields only)
    private static final Schema.DescribeFieldResult[] LOG_FIELD_DESCRIBE_RESULTS = new Schema.DescribeFieldResult[]{
        Auth_Provider_Log__c.Auth_Provider_Name__c.getDescribe(),
        Auth_Provider_Log__c.User__c.getDescribe(),
        Auth_Provider_Log__c.Log_Id__c.getDescribe(),
        Auth_Provider_Log__c.Message__c.getDescribe()
    };

    // Create a list of mapping fields with describes (these are the updateable fields only)
    private static final Schema.DescribeFieldResult[] MAP_FIELD_DESCRIBE_RESULTS = new Schema.DescribeFieldResult[]{
        Auth_Provider_Log__c.Auth_Provider_Name__c.getDescribe(),
        Auth_Provider_Log__c.User__c.getDescribe(),
        Auth_Provider_User_Mapping__c.Last_Auth_Provider_Log__c.getDescribe(),
        Auth_Provider_User_Mapping__c.Last_Login_Date__c.getDescribe(),
        Auth_Provider_User_Mapping__c.Number_of_Logins__c.getDescribe()
    };

    // Log access messages
    private static final String LOG_SOBJECT_ACCESS_MSG = 'The current user is not allowed to CREATE "Auth_Provider_Log__c" records.';
    private static final String LOG_FIELD_ACCESS_MSG   = 'The current user does not have CREATE access on "Auth_Provider_Name__c", "User__c", "Log_Id__c" and "Message__c" fields on the "Auth_Provider_Log__c" sObject.';

    // Mapping access messages
    private static final String MAP_SOBJECT_ACCESS_MSG = 'The current user is not allowed to UPDATE "Auth_Provider_User_Mapping__c" records.';
    private static final String MAP_FIELD_ACCESS_MSG   = 'The current user does not have UPDATE access on the "Last_Login_Date__c","Number_of_Logins__c" and "Last_Auth_Provider_Log__c" fields on the "Auth_Provider_User_Mapping__c" sObject.';

    // Event access messages
    private static final String LOG_EVT_SOBJECT_ACCESS_MSG = 'The current user is not allowed to CREATE "Auth_Provider_Log_Event__e" records.';
    private static final String MAP_EVT_SOBJECT_ACCESS_MSG = 'The current user is not allowed to CREATE "Auth_Provider_User_Mapping_Event__e" records.';

    // Add validation mesages
    @TestVisible private static final String LOG_INPUT_VALIDATION_MSG  = 'The fields "Auth_Provider_Name__c", "User__c", "Log_Id__c" and  "Message__c" on the sObject "Auth_Provider_Log__c" are mandatory and cannot be blank.';
    @TestVisible private static final String MAP_INPUT_VALIDATION_MSG  = 'The fields "Auth_Provider_Name__c" and "User__c" on the sObject "Auth_Provider_User_Mapping__c" are mandatory and cannot be blank.';
    
    // Trigger validation messages
    @TestVisible private static final String INVALID_AUTH_PROVIDER_MSG = 'The Auth Provider with DeveloperName "{0}" does not exist in the metadata. Please check your Auth Provider DeveloperName.';

    // Callable messages
    @TestVisible private static final String INVALID_METHOD_CALLED_MSG = 'The method {0} does not exist on class {1}.';


    /** **************************************************************************************************** **
     **                                           INTERFACE METHODS                                          **
     ** **************************************************************************************************** **/
    global Object call(String action, Map<String, Object> args) {
        switch on action {
            when 'insertLog' {
                insertLog(
                    (String) args.get('authProviderName'),
                    (String) args.get('userId'),
                    (String) args.get('logId'),
                    (String) args.get('message')
                );
                return null;
            }
            when 'checkUserMappingExists' {
                return checkUserMappingExists(
                    (String) args.get('authProviderName'),
                    (String) args.get('userId')
                );
            }
            when 'updateMappingLoginDetails' {
                updateMappingLoginDetails(
                    (String) args.get('authProviderName'),
                    (String) args.get('userId')
                );
                return null;
            }
            when 'getSubjectFromUserMapping' {
                return getSubjectFromUserMapping(
                    (String) args.get('authProviderName'),
                    (String) args.get('userId')
                );
            }
            when else {
                throw new AuthProviderUtilException(INVALID_METHOD_CALLED_MSG);
            }
        }
    }
    
    /** **************************************************************************************************** **
     **                                        PUBLIC SUPPORT METHODS                                        **
     ** **************************************************************************************************** **/
    /**
     * @description    Method to manage the security and input validation for an Auth_Provider_Log__c record
     *                 This takes care of the boilerplate code when this utility is used from an Auth
     *                 Provider Class
     * @param          authProviderName           The DeveloperName of the auth provider
     * @param          userId                     The 18 character Id of the required user
     * @param          logId                      The Id of the related log. Usually this has the
     *                                            format of a GUID
     * @param          message                    The content of the message
     * @note           This code is not bulkified. Due to the nature of how it runs, it will (should)
     *                 only one record at a time.
     * @false-positive PMD.ExcessiveParameterList It's not that many parameters over the threshold of
     *                                            3. Imho this is still fine.
     * @false-positive PMD.ApexCRUDViolation      The CRUD is checked with a utility method so PMD does
     *                                            not pick up on this.
     */
    @SuppressWarnings('PMD.ExcessiveParameterList, PMD.ApexCRUDViolation')
    global static void insertLog(String authProviderName, String userId, String logId, String message){
        
        // Check the current user can create Auth_Provider_Log_Event__e records
        checkLogEventCreateAccess();

        // Validate the input values and specify the exception message to be thrown
        validateInput(
            new String[]{authProviderName,userId,logId,message},
            LOG_INPUT_VALIDATION_MSG
        );

        // Create a new log event and validate field lengths etc
        // These match the lengthts in the log object, so lets use those as they are already described
        Auth_Provider_Log_Event__e logEvent = new Auth_Provider_Log_Event__e(
            Auth_Provider_Name__c = (authProviderName.length() <= LOG_FIELD_DESCRIBE_RESULTS[0].getLength()) ? authProviderName : authProviderName.subString(0, LOG_FIELD_DESCRIBE_RESULTS[0].getLength()),
            User__c               = (userId.length()           <= LOG_FIELD_DESCRIBE_RESULTS[1].getLength()) ? userId           : userId.subString(0,           LOG_FIELD_DESCRIBE_RESULTS[1].getLength()),
            Log_Id__c             = (logId.length()            <= LOG_FIELD_DESCRIBE_RESULTS[2].getLength()) ? logId            : logId.subString(0,            LOG_FIELD_DESCRIBE_RESULTS[2].getLength()),
            Message__c            = (message.length()          <= LOG_FIELD_DESCRIBE_RESULTS[3].getLength()) ? message          : message.subString(0,          LOG_FIELD_DESCRIBE_RESULTS[3].getLength())
        );

        // Publish the event
        Eventbus.publish(logEvent); 
    }


    /**
     * @description Method to validate that a mapping exists, this can be used in in auth provider to
     *              throw a specific error before trying the token callout
     * @param       authProviderName The DeveloperName of the auth provider
     * @param       userId           The 18 character Id of the required user
     * @return      True if a mapping records exists, false by default
     */
    global static Boolean checkUserMappingExists(String authProviderName, String userId){
        return getUserMappingRecord(authProviderName,userId) != null;
    }


    /**
     * @description    Method to update the mapping record's login details on successful token request
     * @param          authProviderName      The DeveloperName of the auth provider
     * @param          userId                The 18 character Id of the required user
     * @false-positive PMD.ApexCRUDViolation The CRUD is checked with a utility method so PMD does not
     *                                       pick up on this.
     */
    @SuppressWarnings('PMD.ApexCRUDViolation')
    global static void updateMappingLoginDetails(String authProviderName, String userId){
        
        // Check the current user can create Auth_Provider_User_Mapping_Event__e records
        checkMappingEventCreateAccess();

        // Validate the input values and specify the exception message to be thrown
        validateInput(
            new String[]{authProviderName,userId},
            MAP_INPUT_VALIDATION_MSG
        );

        // Validate mapping input
        Auth_Provider_User_Mapping_Event__e mappingEvent = new Auth_Provider_User_Mapping_Event__e(
            Auth_Provider_Name__c = (authProviderName.length() <= MAP_FIELD_DESCRIBE_RESULTS[0].getLength()) ? authProviderName : authProviderName.subString(0, MAP_FIELD_DESCRIBE_RESULTS[0].getLength()),
            User__c               = (userId.length()           <= MAP_FIELD_DESCRIBE_RESULTS[1].getLength()) ? userId           : userId.subString(0,           MAP_FIELD_DESCRIBE_RESULTS[1].getLength())
        );

        // Publish the event
        Eventbus.publish(mappingEvent); 
    }


    /**
     * @description Method that returns the contents of the Target_User_Identifier__c field from the
     *              user mapping record that matches the Auth Provider and User Id combination.
     *              If there is no mapping null will be returned. This should be used together with the
     *              check credentials exists method.
     * @param       authProviderName The DeveloperName of the auth provider
     * @param       userId           The 18 character Id of the required user
     * @return      Target_User_Identifier__c value from the related mapping record
     */
    global static String getSubjectFromUserMapping(String authProviderName, String userId){
        return getUserMappingRecord(authProviderName,userId)?.Target_User_Identifier__c;
    }


    /** **************************************************************************************************** **
     **                                       PRIVATE SUPPORT METHODS                                        **
     ** **************************************************************************************************** **/
    /**
     * @description Method to "Lazily" get a user mapping record
     * @param       authProviderName The DeveloperName of the auth provider
     * @param       userId           The 18 character Id of the required user
     * @return      The Auth_Provider_User_Mapping__c record
     */
    private static Auth_Provider_User_Mapping__c getUserMappingRecord(String authProviderName, String userId){
        
        // Lazy loading where the value can be null, so switched to a simple boolean value
        if(!userMappingRetrieved){
            
            // Query the relatd user mapping, the combination of 
            Auth_Provider_User_Mapping__c[] userMappings = [
                SELECT Id, Number_of_Logins__c, Target_User_Identifier__c FROM Auth_Provider_User_Mapping__c
                WHERE User__c = :userId AND Auth_Provider_Name__c = :authProviderName
                WITH SECURITY_ENFORCED LIMIT 1
            ];

            userMapping = (userMappings.isEmpty()) ? null : userMappings[0];
        }

        // Return the log record if it exists
        return userMapping;
    }


    /**
     * @description    Method that updates the "Last Auth Provider Log" field on a user mapping record
     * @param          authProviderLog       The auth provider log that needs to be popoulated
     * @false-positive PMD.ApexCRUDViolation The CRUD is checked with a utility method so PMD does not
     *                                       pick up on this.
     */
    @SuppressWarnings('PMD.ApexCRUDViolation')
    private static void updateRelatedUserMappingLogField(Auth_Provider_Log__c authProviderLog){

        // If no mapping exists nothing has to happen
        if(!checkUserMappingExists(authProviderLog.Auth_Provider_Name__c, authProviderLog.User__c)){
            return;
        }

        // Validate the user has update access
        checkUserMappingUpdateAccess();
        
        // Update the log field value
        userMapping.Last_Auth_Provider_Log__c = authProviderLog.Id;

        // Update the mapping
        update userMapping;
    }


    /** **************************************************************************************************** **
     **                                       TRIGGER UTILITY METHODS                                        **
     ** **************************************************************************************************** **/
    /**
     * @description Method to validate an auth provider exists in the metadata
     * @param       sObjectField The SObjectField object that needs to be referenced
     * @param       records      A list of SObject records
     */
    public static void validateAuthProviderName(SObjectField sObjectField, SObject[] records){

        // Don't run this validation in tests: Auth Providers cannot be mocked in a test
        if(Test.isRunningTest() && ignoreValidationInTest){
            return;
        }
        
        String fieldName = String.valueOf(sObjectField);
        Set<String> authProviderNames = new Set<String>{};
        Set<String> existingAuthProviderNames = new Set<String>{};

        // Get all auth providers in the trigger
        for(SObject record : records){
            authProviderNames.add(((String)record.get(fieldName)).toLowerCase());
        }

        // Get all existing auth provider records
        for(AuthProvider authProvider : [SELECT DeveloperName FROM AuthProvider WHERE DeveloperName IN :authProviderNames WITH SECURITY_ENFORCED]){
            existingAuthProviderNames.add(authProvider.DeveloperName.toLowerCase());
        }

        // Validate for each record that the auth provider exists or add an error to the record
        for(SObject record : records){
            if(!existingAuthProviderNames.contains(((String) record.get(fieldName)).toLowerCase())){
                record.addError(String.format(INVALID_AUTH_PROVIDER_MSG, new String[]{(String) record.get(fieldName)}));
            }
        }
    }


    /**
     * @description Method that updates the owner field based on a different field on the sObject
     * @param       sObjectField The SObjectField object that needs to be referenced
     * @param       records      A list of SObject records
     */
    public static void updateOwner(SObjectField sObjectField, SObject[] records){
        for(SObject record : records){
            record.put('OwnerId', (Id) record.get(String.valueOf(sObjectField)));
        }
    }


    /**
     * @description Method to concatenate multiple fields into a single field to generate a unique
     *              combined valued
     * @param       concatFields The fields to concatenate
     * @param       targetField  The target field to apply the value to
     * @param       records      A list of SObject records
     */
    public static void updateUniqueValidation(SObjectField[] concatFields, SObjectField targetField, SObject[] records){
        for(SObject record : records){
            record.put(
                String.valueOf(targetField),
                record.get(String.valueOf(concatFields[0])) + '_' + record.get(String.valueOf(concatFields[1]))
            );
        }
    }


    /**
     * @description    Method that insert a log record based on a platform event
     * @param          events                        List of Auth_Provider_Log_Event__e records that
     *                                               need to be inserted as a Auth_Provider_Log__c
     *                                               record
     * @false-positive PMD.ApexCRUDViolation         The CRUD is checked with a utility method so PMD
     *                                               does not pick up on this.
     */
    @SuppressWarnings('PMD.ApexCRUDViolation')
    public static void insertLogRecord(Auth_Provider_Log_Event__e[] events){
        
        // If there are no events for some magical reason, dont run the logic
        if(events == null || events.isEmpty()){
            return;
        }

        // Check the current user has access to insert log records
        checkLogInsertAccess();

        // Create a new record, input validations have been done when creating the platofrm event
        Auth_Provider_Log__c log = new Auth_Provider_Log__c(
            Auth_Provider_Name__c = events[0].Auth_Provider_Name__c,
            User__c               = events[0].User__c,
            Log_Id__c             = events[0].Log_Id__c,
            Message__c            = events[0].Message__c
        );

        // Insert the new record
        insert log;

        // Update a related user mapping (if one exists)
        updateRelatedUserMappingLogField(log);
    }


    /**
     * @description Method that updates a user mapping record based on a platform event
     * @param       events List of Auth_Provider_User_Mapping_Event__e records that need to be updated
     */
    public static void updateMappingRecord (Auth_Provider_User_Mapping_Event__e[] events){
        
        // If there are no events for some magical reason, dont run the logic
        if(events == null || events.isEmpty()){
            return;
        }

        // If no mapping exists nothing has to happen
        if(!checkUserMappingExists(events[0].Auth_Provider_Name__c, events[0].User__c)){
            return;
        }

        // Validate the user has update access
        checkUserMappingUpdateAccess();
        
        // Update the last login date to now and up the number of logins by 1
        userMapping.Last_Login_Date__c  = Datetime.now();
        userMapping.Number_of_Logins__c = (userMapping.Number_of_Logins__c == null) ? 1 : userMapping.Number_of_Logins__c + 1;

        // Update the mapping
        update userMapping;
    }


    /** **************************************************************************************************** **
     **                                       PRIVATE UTILITY METHODS                                        **
     ** **************************************************************************************************** **/
    /**
     * @description    Method to validate empty input values when creating the log
     * @param          inputs                    The list of strings to validate if they are blank
     * @param          exceptionMessage          The exception message that will be shown to the user
     * @throws         AuthProviderUtilException Any input that is check is blank (null or empty)
     * @false-positive PMD.OneDeclarationPerLine This is a declaration inside a for loop for
     *                                           optimization. This is still easily readable and has no
     *                                           big impact
     */
    @SuppressWarnings('PMD.OneDeclarationPerLine')
    private static void validateInput(String[] inputs, String exceptionMessage){
        for(Integer i=0, max=inputs.size();i<max;i++){
            if(String.isBlank(inputs[i])){
                throw new AuthProviderUtilException(exceptionMessage);
            }
        }
    }
    

    /**
     * @description    Method to validate INSERT access on the Aut_Provider_Log__c sObject and fields
     * @throws         AuthProviderUtilException A user does not have the correct access level
     * @false-positive PMD.OneDeclarationPerLine This is a declaration inside a for loop for
     *                                           optimization. This is still easily readable and has no
     *                                           big impact
     */
    @SuppressWarnings('PMD.OneDeclarationPerLine')
    private static void checkLogInsertAccess(){
        // sObject Access check
        if(!LOG_DESCRIBE_RESULT.isCreateable()){
            throw new AuthProviderUtilException(LOG_SOBJECT_ACCESS_MSG);
        }
        
        // FLS Check
        for(Integer i=0, max=LOG_FIELD_DESCRIBE_RESULTS.size();i<max;i++){
            if(!LOG_FIELD_DESCRIBE_RESULTS[i].isCreateable()){
                throw new AuthProviderUtilException(LOG_FIELD_ACCESS_MSG);
            }
        }
    }


    /**
     * @description    Method to validate UPDATE access on the Aut_Provider_User_Mapping__c sObject and
     *                 fields
     * @throws         AuthProviderUtilException A user does not have the correct access level
     * @false-positive PMD.OneDeclarationPerLine This is a declaration inside a for loop for
     *                                           optimization. This is still easily readable and has no
     *                                           big impact
     */
    @SuppressWarnings('PMD.OneDeclarationPerLine')
    private static void checkUserMappingUpdateAccess(){
        
        // sObject Access check
        if(!MAP_DESCRIBE_RESULT.isUpdateable()){
            throw new AuthProviderUtilException(MAP_SOBJECT_ACCESS_MSG);
        }
        
        // FLS Check
        for(Integer i=0, max=MAP_FIELD_DESCRIBE_RESULTS.size();i<max;i++){
            if(!MAP_FIELD_DESCRIBE_RESULTS[i].isUpdateable()){
                throw new AuthProviderUtilException(MAP_FIELD_ACCESS_MSG);
            }
        }
    }


    /**
     * @description Method to validate that the current user can create log event records
     */
    private static void checkLogEventCreateAccess(){
        // sObject Access check
        if(!LOG_EVT_DESCRIBE_RESULT.isCreateable()){
            throw new AuthProviderUtilException(LOG_EVT_SOBJECT_ACCESS_MSG);
        }
    }


    /**
     * @description Method to check if the current user can create user mapping event records
     */
    private static void checkMappingEventCreateAccess(){
        // sObject Access check
        if(!MAP_EVT_DESCRIBE_RESULT.isCreateable()){
            throw new AuthProviderUtilException(MAP_EVT_SOBJECT_ACCESS_MSG);
        }
    }


    /** **************************************************************************************************** **
     **                                      PRIVATE EXCEPTION CLASSES                                       **
     ** **************************************************************************************************** **/
    /**
     * @description Custom Exception thrown when there is an issue with any of the utilities
     */
    @TestVisible
    private class AuthProviderUtilException extends Exception{}
}