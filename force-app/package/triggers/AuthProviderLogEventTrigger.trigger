trigger AuthProviderLogEventTrigger on Auth_Provider_Log_Event__e (after insert) {
	AuthProviderUtil.insertLogRecord(trigger.new);
}