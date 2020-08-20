#Changelog

## 1.0.4
### Features Added
- Allowed CredentialSigner to hash (or not) the supplied data prior to siging

### Bugs Fixed
- N/A

## 1.0.3

### Features Added
- Changed signer's language from 'Address' to 'PublicKey'
- Uses java security ECPublicKey to index signers
- Moved to latest version of Azure KeyVault libraries
- Able to sign using a key stored as a hex string in an Azure KeyVault Secret (but signing performed on local machine)

### Bugs Fixed
- Enabled check_licenses gradle task to ensure compliance with Apache 2.0 licensing
