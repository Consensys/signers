#Changelog

## 1.0.15.1
### Features Added
- No code changes from 1.0.15
- Upgrade gradle version

## 1.0.15
### Features Added
- Publish artifacts to Cloudsmith
- Move to tag based release

## 1.0.14
### Features Added
- Managed Identity credentials support in Azure Key Vault

### Bugs fixes
- NA

## 1.0.13
### Features Added
- BLS keystore file (EIP-2335) parsing - make path and UUID fields optional

### Bugs fixes
- NA
 
## 1.10.12
### Features Added
- Change Interlock keystore API fetchKey argument type

### Bugs fixed
- NA

## 1.0.11
### Features Added
- YubiHSM2 as keystore using PKCS11 module. 
- yubihsm-shell integration has been removed.

### Bugs Fixed
- N/A

## 1.0.10
### Features Added
- F-Secure Interlock for Armory II as keystore

### Bugs Fixed
- N/A

## 1.0.9
### Features Added
- YubiHSM2 as keystore

### Bugs Fixed
- N/A

## 1.0.8
### Features Added
- N/A

### Bugs Fixed
- Correctly handle null/exceptions when raised by mapper passed into Azure Key Vault

## 1.0.7
### Features Added
- Added ability to map all secrets in Azure Key Vault to a business object

### Bugs Fixed
- N/A

## 1.0.6
### Features Added
- "Raw" toml files can now be created (toml file contains a single private key hex string)
- Add ability to list all secret names in an Azure Key Vault

### Bugs Fixed
- N/A

## 1.0.5
### Features Added
- Applied new unicode normalization rules for EIP2335 keystore passwords. 
- AzureKeyVaultSigner can be configured to not hash data prior to signing

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
