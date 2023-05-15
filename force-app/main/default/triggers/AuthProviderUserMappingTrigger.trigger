trigger AuthProviderUserMappingTrigger on Auth_Provider_User_Mapping__c (before insert, before update) {
	AuthProviderUtil.validateAuthProviderName(
		Auth_Provider_User_Mapping__c.Auth_Provider_Name__c,
		trigger.new
	); 
}