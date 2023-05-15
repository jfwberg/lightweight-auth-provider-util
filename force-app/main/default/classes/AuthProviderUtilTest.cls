/**
 * @author      Justus van den Berg (jfwberg@gmail.com)
 * @date        May 2023
 * @copyright   (c) 2023 Justus van den Berg
 * @license     MIT (See LICENSE file in the project root)
 * @description Class containing the Auth Provider Utilities Test Methods
 */
@IsTest
private with sharing class AuthProviderUtilTest {
	
	// Test data values
	private static String authProviderName	= 'myAuthProvider';
	private static String userId			= UserInfo.getUserId();
	private static String targetUserId		= UserInfo.getUserId().toUpperCase();
	private static String logId				= EncodingUtil.convertToHex(Crypto.generateAESKey(128));
	private static String message			= '(Error) Message content';


	/**
	 * @description Method to test inserting a log without an existing mapping record
	 */
	@IsTest
	static void testUtilitiesWithoutMapping(){
		
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
		
		// Create a new user mapping record
		Auth_Provider_User_Mapping__c userMapping = new Auth_Provider_User_Mapping__c(
			Auth_Provider_Name__c = authProviderName,
			User__c = userId,
			Target_User_Identifier__c = targetUserId
		);
		insert userMapping;

		// Method to insert an (error) log. Can be used for a success as well, but that should be checked in the external system
		AuthProviderUtil.insertLog(
			authProviderName,
			userId,
			logId,
			message
		);

		// Query the user mapping, this will fail if there is no user mapping logged
		userMapping = [	SELECT Id, Last_Auth_Provider_Log__c, Last_Login_Date__c, Number_of_Logins__c
						FROM Auth_Provider_User_Mapping__c WHERE Last_Auth_Provider_Log__c != null LIMIT 1
					];

		// Validate expected updates on the mapping record
		System.assertEquals(true , userMapping.Last_Auth_Provider_Log__c!= null,'Expected no auth provider log');
		System.assertEquals(true , userMapping.Last_Login_Date__c		== null,'Expected no last login date to be populated');
		System.assertEquals(true , userMapping.Number_of_Logins__c		== 0,	'Expected number of logins to be 0');
		
		// Update the mapping details on the user mapping record
		AuthProviderUtil.updateMappingLoginDetails(
			authProviderName,
			userId
		);

		// Query the user mapping again now the login details have been updated
		userMapping = [	SELECT Id, Last_Auth_Provider_Log__c, Last_Login_Date__c, Number_of_Logins__c
						FROM Auth_Provider_User_Mapping__c WHERE Last_Auth_Provider_Log__c != null LIMIT 1
					];

		// Validate expected updates on the mapping record
		System.assertEquals(true , userMapping.Last_Login_Date__c	!= null,'Expected a last login date to be populated');
		System.assertEquals(true , userMapping.Number_of_Logins__c	== 1,	'Expected number of logins to be 1');
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
}