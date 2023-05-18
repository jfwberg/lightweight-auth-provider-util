try{
	
	// Test data
	String authProviderName	= 'AuthProviderUtil';
	String userId			= UserInfo.getUserId();
	String logId			= EncodingUtil.convertToHex(Crypto.generateAESKey(128));
	String message			= '(Error) Message content';

	// Method to check a mapping record exists, you can throw an error before trying to fetch the
	// token if no mapping exists.
	Boolean mappingRecordExists = lwt.AuthProviderUtil.checkUserMappingExists(
		authProviderName,
		userId
	);
			
			
	// Method to insert an (error) log. Can be used for a success as well, but that should be checked in the external system
	lwt.AuthProviderUtil.insertLog(
		authProviderName,
		userId,
		logId,
		message 
	);

	// Method to update the login details, sets the last login date and updates the counter
	lwt.AuthProviderUtil.updateMappingLoginDetails(
		authProviderName,
		userId
	);

}catch(Exception e){
	System.debug(e.getMessage());
}