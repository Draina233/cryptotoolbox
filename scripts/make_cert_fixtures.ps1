# Generate certificate chain / CRL / CMS fixtures with openssl 3.x (ASCII paths only).
$ErrorActionPreference = 'Continue'
$root = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\tests\vectors\certs'))
New-Item -ItemType Directory -Force -Path $root | Out-Null
Set-Location $root
$openssl = 'openssl'

function Op([scriptblock]$sb) {
    $out = & $sb 2>&1
    if ($LASTEXITCODE -ne 0) { throw "openssl failed ($LASTEXITCODE): $out" }
    Write-Output "OK: $($sb.ToString().Substring(0, [Math]::Min(80, $sb.ToString().Length)))"
}

function Gen-RsaChain([string]$Prefix) {
    Op { & $openssl req -x509 -newkey rsa:2048 -keyout "$Prefix-root.key" -out "$Prefix-root.crt" -days 3650 -nodes -subj "/CN=$Prefix Root CA/O=TestOrg/C=CN" -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" }
    Op { & $openssl req -newkey rsa:2048 -keyout "$Prefix-int.key" -out "$Prefix-int.csr" -nodes -subj "/CN=$Prefix Intermediate CA/O=TestOrg/C=CN" }
    @"
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
"@ | Out-File -Encoding ascii "$Prefix-int.ext"
    Op { & $openssl x509 -req -in "$Prefix-int.csr" -CA "$Prefix-root.crt" -CAkey "$Prefix-root.key" -CAcreateserial -out "$Prefix-int.crt" -days 3650 -sha256 -extfile "$Prefix-int.ext" }
    Op { & $openssl req -newkey rsa:2048 -keyout "$Prefix-leaf.key" -out "$Prefix-leaf.csr" -nodes -subj "/CN=$Prefix leaf.example.com/O=TestOrg/C=CN" }
    @"
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:leaf.example.com
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
"@ | Out-File -Encoding ascii "$Prefix-leaf.ext"
    Op { & $openssl x509 -req -in "$Prefix-leaf.csr" -CA "$Prefix-int.crt" -CAkey "$Prefix-int.key" -CAcreateserial -out "$Prefix-leaf.crt" -days 365 -sha256 -extfile "$Prefix-leaf.ext" }
}

function Gen-EcChain([string]$Prefix) {
    foreach ($name in @('root', 'int', 'leaf')) {
        Op { & $openssl ecparam -name prime256v1 -genkey -noout -out "$Prefix-$name.key" }
    }
    Op { & $openssl req -x509 -key "$Prefix-root.key" -out "$Prefix-root.crt" -days 3650 -subj "/CN=$Prefix ECDSA Root CA/O=TestOrg/C=CN" -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" }
    Op { & $openssl req -new -key "$Prefix-int.key" -out "$Prefix-int.csr" -subj "/CN=$Prefix ECDSA Intermediate CA/O=TestOrg/C=CN" }
    @"
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
"@ | Out-File -Encoding ascii "$Prefix-int.ext"
    Op { & $openssl x509 -req -in "$Prefix-int.csr" -CA "$Prefix-root.crt" -CAkey "$Prefix-root.key" -CAcreateserial -out "$Prefix-int.crt" -days 3650 -sha256 -extfile "$Prefix-int.ext" }
    Op { & $openssl req -new -key "$Prefix-leaf.key" -out "$Prefix-leaf.csr" -subj "/CN=$Prefix-ecdsa.example.com/O=TestOrg/C=CN" }
    @"
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:ecdsa.example.com
"@ | Out-File -Encoding ascii "$Prefix-leaf.ext"
    Op { & $openssl x509 -req -in "$Prefix-leaf.csr" -CA "$Prefix-int.crt" -CAkey "$Prefix-int.key" -CAcreateserial -out "$Prefix-leaf.crt" -days 365 -sha256 -extfile "$Prefix-leaf.ext" }
}

function Gen-Sm2Chain([string]$Prefix) {
    foreach ($name in @('root', 'leaf')) {
        Op { & $openssl ecparam -name SM2 -genkey -noout -out "$Prefix-$name.key" }
    }
    Op { & $openssl req -x509 -key "$Prefix-root.key" -out "$Prefix-root.crt" -days 3650 -sm3 -subj "/CN=$Prefix SM2 Root CA/O=TestOrg/C=CN" -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" }
    Op { & $openssl req -new -key "$Prefix-leaf.key" -out "$Prefix-leaf.csr" -sm3 -subj "/CN=$Prefix-sm2.example.com/O=TestOrg/C=CN" }
    @"
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:sm2.example.com
"@ | Out-File -Encoding ascii "$Prefix-leaf.ext"
    Op { & $openssl x509 -req -in "$Prefix-leaf.csr" -CA "$Prefix-root.crt" -CAkey "$Prefix-root.key" -CAcreateserial -out "$Prefix-leaf.crt" -days 365 -sm3 -extfile "$Prefix-leaf.ext" }
}

Gen-RsaChain 'rsa'
Gen-EcChain 'ec'
Gen-Sm2Chain 'sm2'

# 非 CA 证书签发的终端证书（用于测试 CA 基本约束检查）
Op { & $openssl req -newkey rsa:2048 -keyout nonca-leaf.key -out nonca-leaf.csr -nodes -subj "/CN=nonca leaf.example.com/O=TestOrg/C=CN" }
Op { & $openssl x509 -req -in nonca-leaf.csr -CA ec-leaf.crt -CAkey ec-leaf.key -CAcreateserial -out nonca-leaf.crt -days 100 -sha256 }

'CMS test content' | Out-File -Encoding ascii 'cms-data.txt'
Op { & $openssl cms -sign -binary -in cms-data.txt -signer rsa-leaf.crt -inkey rsa-leaf.key -outform DER -out cms-rsa-attached.p7s -nodetach -md sha256 }
Op { & $openssl cms -sign -binary -in cms-data.txt -signer rsa-leaf.crt -inkey rsa-leaf.key -outform DER -out cms-rsa-detached.p7s -md sha256 }
Op { & $openssl cms -sign -binary -in cms-data.txt -signer sm2-leaf.crt -inkey sm2-leaf.key -outform DER -out cms-sm2-attached.p7s -nodetach -md sm3 }
Op { & $openssl cms -sign -binary -in cms-data.txt -signer ec-leaf.crt -inkey ec-leaf.key -outform DER -out cms-ec-attached.p7s -nodetach -md sha256 }

$caDir = Join-Path $root 'ca'
New-Item -ItemType Directory -Force -Path (Join-Path $caDir 'newcerts') | Out-Null
[System.IO.File]::WriteAllText((Join-Path $caDir 'index.txt'), '')
Set-Content -Path (Join-Path $caDir 'serial') -Value '1000' -Encoding ascii
Set-Content -Path (Join-Path $caDir 'crlnumber') -Value '1000' -Encoding ascii
@"
[ ca ]
default_ca = CA_default
[ CA_default ]
dir = ca
database = ca/index.txt
new_certs_dir = ca/newcerts
certificate = rsa-root.crt
private_key = rsa-root.key
serial = ca/serial
crlnumber = ca/crlnumber
default_md = sha256
default_days = 365
default_crl_days = 30
policy = policy_any
[ policy_any ]
commonName = optional
organizationName = optional
countryName = optional
"@ | Out-File -Encoding ascii 'ca.cnf'
Op { & $openssl ca -config 'ca.cnf' -gencrl -out 'rsa-root.crl' }
Op { & $openssl crl -in 'rsa-root.crl' -outform DER -out 'rsa-root.crl.der' }

Get-ChildItem -File | Where-Object { $_.Extension -in '.crt', '.crl', '.p7s', '.der' } |
    Select-Object Name, Length | Format-Table -AutoSize
Write-Output 'done'
