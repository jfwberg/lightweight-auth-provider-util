trigger AuthProviderLoginHistoryTrigger on Auth_Provider_Login_History__c (before insert, before update) {
    AuthProviderUtil.validateAuthProviderName(
        Auth_Provider_Login_History__c.Auth_Provider_Name__c,
        trigger.new
    );
}