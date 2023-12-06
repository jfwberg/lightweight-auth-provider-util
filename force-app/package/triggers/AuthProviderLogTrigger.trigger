trigger AuthProviderLogTrigger on Auth_Provider_Log__c (before insert, before update) {
    AuthProviderUtil.validateAuthProviderName(
        Auth_Provider_Log__c.Auth_Provider_Name__c,
        trigger.new
    ); 
}