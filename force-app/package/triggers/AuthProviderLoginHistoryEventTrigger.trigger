trigger AuthProviderLoginHistoryEventTrigger on Auth_Provider_Login_History_Event__e (after insert) {
    AuthProviderUtil.insertHistoryRecord(trigger.new);
}