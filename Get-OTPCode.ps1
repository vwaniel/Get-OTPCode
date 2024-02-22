function Get-OTPCode {
	<#
	.SYNOPSIS
		Generate a one-time passcode (OTP) from seed data.
	.DESCRIPTION
		Generate a one-time passcode (OTP) from seed data.  Optionally, specify the number of seconds before the OTP code refreshes, the length of the OTP code, and the date/time to use when generating the code.
	.PARAMTER OTPSeed
		A base32 string containing the OTP seed data.  Must be specified as System.SecureString.
	.PARAMETER OTPRefreshSeconds
		The number of seconds before an OTP code is refreshed.  The default is 30 seconds.
	.PARAMETER OTPLength
		The length of the OTP code, between 1 and 10 digits.  The default is 6 digits.
	.PARAMETER OTPDateTime
		The date/time used to generate the OTP code.  The default is the current date/time.
	.EXAMPLE
		PS> "XXXXXXXXXXXXXXXX" | ConvertTo-SecureString -AsPlainText -Force | Get-OTPCode
		
		Converts the seed "XXXXXXXXXXXXXXXX" into a secure string and generates an OTP code using the default parameters (6 digits, 30 second refresh).
	.EXAMPLE
		PS> "XXXXXXXXXXXXXXXX" | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString | Out-File .\encrypted_seed.txt
		PS> Get-Content .\encrypted_seed.txt | ConvertTo-SecureString | Get-OTPCode
		
		Converts the seed "XXXXXXXXXXXXXXXX" into a secure string, converts it to an encrypted text string, and writes it to a file.
		Reads the contents of a file containing an encrypted string, converts it to a secure string, and passes it to Get-OTPCode.
	#>
	[cmdletbinding()]
	param (
		[Parameter(Mandatory=$true,Position=1,ValueFromPipeline=$true)][securestring]$OTPSeed,
		[Parameter(Mandatory=$false)][int]$OTPRefreshSeconds = 30,
		[Parameter(Mandatory=$false)][ValidateRange(1,10)][int]$OTPLength = 6,
		[Parameter(Mandatory=$false)][datetime]$OTPDateTime = $(Get-Date)
	)
	
	function Convert-DecimalToHex($in) {
		return ([String]("{0:x}" -f [Int64]$in)).ToUpper()
	}

	function Convert-HexToDecimal($in) {
		return [Convert]::ToInt64($in,16)
	}

	function Convert-HexStringToByteArray($String) {
		return $String -split '([A-F0-9]{2})' | foreach-object { if ($_) {[System.Convert]::ToByte($_,16)}}
	}

	function Convert-Base32ToHex([String]$base32) {
		$base32 = $base32.ToUpper()
		$base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
		$bits = ""
		$hex = ""

		# convert char-by-char of input into 5-bit chunks of binary
		foreach ($char in $base32.ToCharArray()) {
			$tmp = $base32chars.IndexOf($char)
			$bits = $bits + (([Convert]::ToString($tmp,2))).PadLeft(5,"0")
		}

		# leftpad bits with 0 until length is a multiple of 4
		while ($bits.Length % 4 -ne 0) {
			$bits = "0" + $bits
		}
		 
		# convert binary chunks of 4 into hex
		for (($tmp = $bits.Length -4); $tmp -ge 0; $tmp = $tmp - 4) {
			$chunk = $bits.Substring($tmp, 4);
			$dec = [Convert]::ToInt32($chunk,2)
			$h = Convert-DecimalToHex $dec
			$hex = $h + $hex  
		}
		return $hex
	}

	function Get-EpochHex {
		param (
			[Parameter(Mandatory=$true,Position=1)][int]$OTPFrefreshSeconds,
			[Parameter(Mandatory=$true,Position=2)][datetime]$OTPDateTime
		)
		$unixEpoch = ($OTPDateTime.ToUniversalTime().Ticks - 621355968000000000) / 10000000
		$h = Convert-DecimalToHex ([Math]::Floor($unixEpoch / $OTPRefreshSeconds))
		return $h.PadLeft(16,"0")
	}

	function Get-HMAC($key, $time) {
		$hashAlgorithm = New-Object System.Security.Cryptography.HMACSHA1
		$hashAlgorithm.key = Convert-HexStringToByteArray $key
		$signature = $hashAlgorithm.ComputeHash((Convert-HexStringToByteArray $time))
		$result = [string]::join("", ($signature | % {([int]$_).toString('x2')}))
		$result = $result.ToUpper()
		return $result
	}

	function Get-OTPFromHMAC {
		param(
			[Parameter(Mandatory=$true,Position=1)][string]$HMAC,
			[Parameter(Mandatory=$true,Position=2)][int]$OTPLength
		)
		$offset = Convert-HexToDecimal($HMAC.Substring($HMAC.Length -1))
		$p1 = Convert-HexToDecimal($HMAC.Substring($offset*2,8))
		$p2 = Convert-HexToDecimal("7fffffff")
		[string]$otp = $p1 -band $p2
		$otp =  $otp.Substring($otp.Length - $OTPLength, $OTPLength)
		return $otp
	}
	
	$objOTP = New-Object PSObject -Property @{
		"Key" = $(Convert-Base32ToHex $([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR(($OTPSeed)))) | ConvertTo-SecureString -AsPlainText -Force);
		"OTPRefreshSeconds" = $OTPRefreshSeconds;
		"OTPLength" = $OTPLength;
		"OTPDateTime" = $OTPDateTime;
		"HexEpochTime" = "";
		"HMAC" = "";
		"OTP" = "";
	}

	$objOTP.HexEpochTime = Get-EpochHex $OTPRefreshSeconds $OTPDateTime
	$objOTP.HMAC = Get-HMAC $([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR(($objOTP.Key)))) $objOTP.HexEpochTime
	$objOTP.OTP  = Get-OTPFromHMAC $objOTP.HMAC $OTPLength

	[GC]::Collect()

	return $objOTP
}