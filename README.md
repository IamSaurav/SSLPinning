# SSL Pinning
iOS sample app for SSL pinning


//Command to fetch SSL certificate from domain:
openssl s_client -connect www.bitmountn.com:443 -showcerts < /dev/null | openssl x509 -outform DER > bitmountn.der

//Following are snippets are in Swift 5:
// Fetch certificate from SecTrust which comes as Authentication Challange. 
func serverSSLCertificate(_ serverTrust: SecTrust) -> SecCertificate? {
    var trustEvalError: UnsafeMutablePointer<CFError?>?
    // It validates a certificate by verifying its signature plus the signatures of the certificates in its certificate chain according to the policy
    let isTrusted = SecTrustEvaluateWithError(serverTrust, trustEvalError)
    guard isTrusted else { print(trustEvalError as Any); return .none }
    // There can be more than one certificate, or less also.
    guard SecTrustGetCertificateCount(serverTrust) > 0 else { return .none }
    // The first certificate is the primary one which needs to be validated.
    let certificate: SecCertificate? = SecTrustGetCertificateAtIndex(serverTrust, 0)
    return certificate
}

// To fetch public key of SSL certificate:
func publicKey(_ certificate: SecCertificate) -> String? {
    // Got public key in SecKey format, for equality check we need in Data/String format.
    // Because our pinned public key hash is in String format.
    let serverSSLPublicKey: SecKey? = SecCertificateCopyKey(certificate)
    var publicKeyError: UnsafeMutablePointer<Unmanaged<CFError>?>?
    guard let serverSSLPublicKeyData = SecKeyCopyExternalRepresentation(serverSSLPublicKey!, publicKeyError ) as Data?, publicKeyError == .none else {return .none}
    // This is the final public key string.
    let serverSSLPublicKeyString = serverSSLPublicKeyData.base64EncodedString()
    return serverSSLPublicKeyString
}

//To get sha256 hash from SSL certificate:
func sha256(_ certificate: SecCertificate) -> String? {
    let certData = SecCertificateCopyData(certificate) as Data
    let certStr = certData.base64EncodedString()
    return sha256(certStr)
}

//To get sha256 data hash from certificate data:
func sha256(_ data: Data) -> Data? {
    guard let dataBuffer = NSMutableData(length: Int(CC_SHA256_DIGEST_LENGTH)) else { return nil }
    CC_SHA256((data as NSData).bytes, CC_LONG(data.count), dataBuffer.mutableBytes.assumingMemoryBound(to: UInt8.self))
    return dataBuffer as Data
}

//To get sha256 hash string from certificate string:
func sha256(_ str: String) -> String? {
    guard let data = str.data(using: String.Encoding.utf8), let shaData = sha256(data)
        else { return nil }
    return shaData.base64EncodedString()
}
