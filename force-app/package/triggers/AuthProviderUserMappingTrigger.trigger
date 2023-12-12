trigger AuthProviderUserMappingTrigger on Auth_Provider_User_Mapping__c (before insert, before update) {
	
	// Validate the auth provider name
	AuthProviderUtil.validateAuthProviderName(
		Auth_Provider_User_Mapping__c.Auth_Provider_Name__c,
		trigger.new
	); 

	// Update the validation record
	AuthProviderUtil.updateUniqueValidation(
		new SObjectField[]{Auth_Provider_User_Mapping__c.Auth_Provider_Name__c, Auth_Provider_User_Mapping__c.User__c},
		Auth_Provider_User_Mapping__c.Auth_Provider_User_Id_Validation__c,
		trigger.new
	);
}