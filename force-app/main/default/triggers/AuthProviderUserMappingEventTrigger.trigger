trigger AuthProviderUserMappingEventTrigger on Auth_Provider_User_Mapping_Event__e (after insert) {
	AuthProviderUtil.updateMappingRecord(trigger.new);
}