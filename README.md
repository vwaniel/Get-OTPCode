# Get-OTPCode
Powershell function that generates OTP codes using HMAC-SHA1 from Base 32 shared secrets.  Useful for programatically authenticating to APIs/systems that are secured with multi-factor authentication.

## Installation/Loading
```console
Import-Module .\Get-OTPCode.ps1
```

## Usage
The function requires that the OTP seed data is encrypted in a `[System.Security.SecureString]` object, as the seed data should be considered as sensitive as a password and therefore should be stored/handled in a secure manner.  If the OTP seed is `XXXXXXXXXXXXXXXX` it can be converted to a `[System.Security.SecureString]` via the following command:
```console
'XXXXXXXXXXXXXXXX' | ConvertTo-SecureString -AsPlainText -Force
```

Once the seed has been converted it can be passed to the Get-OTPCode function:
```console
'XXXXXXXXXXXXXXXX' | ConvertTo-SecureString -AsPlainText -Force | Get-OTPCode

HMAC              : 506DE5F42A3716B6FFC8938A99513AB7BB97CDB3
OTPLength         : 6
OTPDateTime       : 2/21/2024 6:33:58 PM
OTP               : 923670
OTPRefreshSeconds : 30
HexEpochTime      : 0000000003650503
Key               : System.Security.SecureString
```

The user may wish to store the seed data as an encrypted string in a text file.  This allows the seed data to be stored securely and decrypted only at the time when the OTP code is being generated.
Convert the seed data to an encrypted string and write it to a file:
```console
'XXXXXXXXXXXXXXXX' | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString | Out-File .\encrypted_seed.txt
```

Get the encrypted string, convert it to a `[System.Security.SecureString]`, and pass it to Get-OTPCode:
```console
Get-Content .\encrypted_seed.txt | ConvertTo-SecureString | Get-OTPCode
```
