//
//  ViewController.swift
//  SSLPinningDemo
//
//  Created by Saurav Satpathy on 4/21/20.
//  Copyright © 2020 bitMountn. All rights reserved.
//

import UIKit
import Security
import CommonCrypto
import CryptoKit
import WebKit

class ViewController: UIViewController, URLSessionDelegate {

    @IBOutlet weak var webView: WKWebView!
    @IBOutlet weak var reloadButton: UIButton!
    @IBOutlet weak var messageLabel: UILabel!
    
    let pinnedCertificateHash = "sMzPGEYbmnXjU/MKJiBs9JictExakx7d0IW21i48fCc="
    let pinnedPublicKeyHash: String = "6J6VLPaNas3DSWWd2rS0JTUXr31EqD6L/QgWHVYDiTI="

    override func viewDidLoad() {
        super.viewDidLoad()
        sendRequest()
    }
    
    func sendRequest() {
        let url = URL(string: "https://www.bitmountn.com/")!
        let session = URLSession( configuration: URLSessionConfiguration.ephemeral, delegate: self, delegateQueue: .none)
        let task = session.dataTask(with: url as URL, completionHandler: { (data, response, error) -> Void in
            guard error == nil, data != nil else { self.showError(error: error); return }
            self.loadData(data!, url)
        })
        task.resume()
    }
    func loadData(_ data: Data, _ url: URL) {
        DispatchQueue.main.async {
            self.webView.load(data, mimeType: "text/html", characterEncodingName: "UTF-8", baseURL: url)
        }
    }
    func showError(error: Error?) {
        DispatchQueue.main.async {
            self.messageLabel.text = "Pinning status: " + (error == nil ? "" : error!.localizedDescription)
        }
    }
    @IBAction func onRelaodTap() {
        sendRequest()
    }
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust else {return}
        guard let serverTrustInfo = challenge.protectionSpace.serverTrust,
            let certificate = serverSSLCertificate(serverTrustInfo) else {return}
        
        // Either of the below methods "Public key pinning" or "Certificate pinning" can be done
//        guard let publicKeySha256 = sha256(certificate) else {return}
//        if pinnedPublicKeyHash == sha256(serverSSlPublicKey) {
//            completionHandler(.useCredential, URLCredential.init(trust: serverTrustInfo))
//        }else{
//            completionHandler(.cancelAuthenticationChallenge, nil)
//        }
        
        if pinnedCertificateHash == sha256(certificate) {
            completionHandler(.useCredential, URLCredential.init(trust: serverTrustInfo))
        }else{
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
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
    func pinnedCertificate() -> SecCertificate? {
        guard let certPath = Bundle.main.path(forResource: "bitmountn", ofType: "crt") else { return .none }
        guard let fileData = try? Data(contentsOf: URL(fileURLWithPath: certPath)) else {return .none}
        let certificate = SecCertificateCreateWithData(.none, fileData as CFData)
        return certificate
    }
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
    func sha256(_ certificate: SecCertificate) -> String? {
        let certData = SecCertificateCopyData(certificate) as Data
        let certStr = certData.base64EncodedString()
        return sha256(certStr)
    }
    func sha256(_ data: Data) -> Data? {
        guard let dataBuffer = NSMutableData(length: Int(CC_SHA256_DIGEST_LENGTH)) else { return nil }
        CC_SHA256((data as NSData).bytes, CC_LONG(data.count), dataBuffer.mutableBytes.assumingMemoryBound(to: UInt8.self))
        return dataBuffer as Data
    }
    func sha256(_ str: String) -> String? {
        guard let data = str.data(using: String.Encoding.utf8), let shaData = sha256(data)
            else { return nil }
        return shaData.base64EncodedString()
    }
    
    
    
    
    
    /*
       func pinnedCertificateSHA256() -> String? {
           guard let certPath = Bundle.main.path(forResource: "bitmountn", ofType: "crt") else { return .none }
           guard let fileData = try? Data(contentsOf: URL(fileURLWithPath: certPath)) else {return .none}
           // Even a SecCertificate can be created from data.
           // let certificate = SecCertificateCreateWithData(.none, fileData as CFData)
           let certificateDataStr = fileData.base64EncodedString()
           return sha256(certificateDataStr)
       }
    */
    
}



                    
