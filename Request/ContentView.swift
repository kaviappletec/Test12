//
//  ContentView.swift
//  Request
//
//  Created by Kavisha on 4/15/24.
//

import SwiftUI
import CommonCrypto
import Foundation


struct ContentView: View {
    let BuildVersion = "19H370";
    let Variant = "iPhone";
    let ModelNumber = "MKR12";
    let ProductType = "iPhone8,1";
    let iOS = "15.8";
    let UniqueChipID = "5167774325943337";
    let UniqueDeviceID = "cf261e21f352271f82818770551913bdab14fc74";
    
    var body: some View {
        VStack {
            Image(systemName: "globe")
                .imageScale(.large)
                .foregroundStyle(.tint)
            Button("Button") {
                self.sendPostRequest()
            }
            Text("Hello, world!")
        }
        .padding()
    }
    func sendPostRequest() {
        // URL and parameters
        let urlString = "https://albert.apple.com/WebObjects/ALUnbrick.woa/wa/deviceActivation"
        let params = [
            "activation-info": "\(FuncActivationToken)"
        ]
        
        // Create URL object
        guard let url = URL(string: urlString) else {
            print("Error: Invalid URL")
            return
        }
        
        // Create request object
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        
        // Encode parameters
        let postData = params.map { key, value in
            return "\(key)=\(value)"
        }.joined(separator: "&")
        
        // Set request body
        request.httpBody = postData.data(using: .utf8)
        
        // Disable SSL certificate verification
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.setValue("nocheck", forHTTPHeaderField: "SSL-Cert-Verification")
        
        // Send the request
        let task = URLSession.shared.dataTask(with: request) { data, response, error in
            if let error = error {
                print("Error: \(error)")
                return
            }
            
            // Handle response
            if let data = data, let responseString = String(data: data, encoding: .utf8) {
                print("Response: \(responseString)")
            }
        }
        task.resume()
    }
    let activationInfoXML = """
 <?xml version="1.0" encoding="UTF-8"?>
 <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
 <plist version="1.0">
 <dict>
       <key>ActivationRandomness</key>
       <string>(GUID)</string>
       <key>ActivationRequiresActivationTicket</key>
       <true/>
       <key>ActivationState</key>
       <string>Unactivated</string>
       <key>BasebandMasterKeyHash</key>
       <string>(Hash of hardware IDs)<string>
       <key>BasebandThumbprint</key>
       <string>(Hash of hardware IDs not directly used as a key - the TEA key can be derived from this)<string>
       <key>BuildVersion</key>
       <string>8A306</string>
       <key>DeviceCertRequest</key>
       
       (base64 encoded cert)
       
       <key>DeviceClass</key>
       <string>(String ENUM "iPhone", "iPod", "iPod touch", "iPad")</string>
       <key>IntegratedCircuitCardIdentity</key>
       <string>(ICCID as base-10 string)</string>
       <key>InternationalMobileEquipmentIdentity</key>
       <string>(IMEI as base-10 string)</string>
       <key>InternationalMobileSubscriberIdentity</key>
       <string>(IMSI as base-10 string)</string>
       <key>ModelNumber</key>
       <string>MC135</string>
       <key>PhoneNumber</key>
       <string>(String like "+1 (555) 555-5555")</string>
       <key>ProductType</key>
       <string>iPhone2,1</string>
       <key>ProductVersion</key>
       <string>4.0.1</string>
       <string>SIMGID1</string>
       
       (base64-encoded binary GID1)
       
       <string>SIMGID2</string>
       
       (base64-encoded binary GID2)
       
       <key>SIMStatus</key>
       <string>(ENUM kCTSIMSupportSIMStatusReady kCTSIMSupportSIMStatusNotReady kCTSIMSupportSIMStatusOperatorLocked)</string>
       <key>SerialNumber</key>
       <string>...</string>
       <key>SupportsPostponement</key>
       <true/>
       <key>UniqueChipID</key>
       <integer>...</integer>
       <key>UniqueDeviceID</key>
       <string>(hex UUID)</string>
 </dict>
 </plist>
"""

    let ActivationToken = """
<dict>
       <key>ActivationInfoComplete</key>
       <true/>
       <key>ActivationInfoXML</key>
       <data></data>
       <key>FairPlayCertChain</key>
       <data></data>
       <key></key>
       <data></data>
 </dict>
"""
    
}

func CreatingActivationToken(){
    //Activation Token Plist
    func FuncActivationToken(){
        let ActivationToken = """
     <dict>
           <key>ActivationInfoComplete</key>
           <true/>
           <key>ActivationInfoXML</key>
           <data>\(ActivationXML)</data>
           <key>FairPlayCertChain</key>
           <data>\(FairPlayCertCain)
           <key>FairPlaySignature</key>
           <data>\(ActivationInfoXMLSignature)</data>
           
     </dict>
    """
    }
    
    //Creating FairPlaySignature
    
    // Assuming private key is in PEM format
    let privateKeyPEM = """
    -----BEGIN RSA PRIVATE KEY-----\nMIICWwIBAAKBgQC3BKrLPIBabhpr+4SvuQHnbF0ssqRIQ67/1bTfArVuUF6p9sdc\nv70N+r8yFxesDmpTmKitLP06szKNAO1k5JVk9/P1ejz08BMe9eAb4juAhVWdfAIy\naJ7sGFjeSL015mAvrxTFcOM10F/qSlARBiccxHjPXtuWVr0fLGrhM+/AMQIDAQAB\nAoGACGW3bHHPNdb9cVzt/p4Pf03SjJ15ujMY0XY9wUm/h1s6rLO8+/10MDMEGMlE\ndcmHiWRkwOVijRHxzNRxEAMI87AruofhjddbNVLt6ppW2nLCK7cEDQJFahTW9GQF\nzpVRQXXfxr4cs1X3kutlB6uY2VGltxQFYsj5djv7D+A72A0CQQDZj1RGdxbeOo4X\nzxfA6n42GpZavTlM3QzGFoBJgCqqVu1JQOzooAMRT+NPfgoE8+usIVVB4Io0bCUT\nWLpkEytTAkEA11rzIpGIhFkPtNc/33fvBFgwUbsjTs1V5G6z5ly/XnG9ENfLblgE\nobLmSmz3irvBRWADiwUx5zY6FN/Dmti56wJAdiScakufcnyvzwQZ7Rwp/61+erYJ\nGNFtb2Cmt8NO6AOehcopHMZQBCWy1ecm/7uJ/oZ3avfJdWBI3fGv/kpemwJAGMXy\noDBjpu3j26bDRz6xtSs767r+VctTLSL6+O4EaaXl3PEmCrx/U+aTjU45r7Dni8Z+\nwdhIJFPdnJcdFkwGHwJAPQ+wVqRjc4h3Hwu8I6llk9whpK9O70FLo1FMVdaytElM\nyqzQ2/05fMb7F6yaWhu+Q2GGXvdlURiA3tY0CsfM0w==\n-----END RSA PRIVATE KEY-----
    """

    // Convert PEM key to Data
    guard let privateKeyData = Data(base64Encoded: privateKeyPEM), let privateKey = try? SecKeyCreateWithData(privateKeyData as CFData, [
        kSecAttrKeyType: kSecAttrKeyTypeRSA,
        kSecAttrKeyClass: kSecAttrKeyClassPrivate,
        ] as CFDictionary, nil) else {
            fatalError("Failed to load private key")
    }

    // Prepare ActivationInfoXML
    let ActivationInfoXML = "\(activationInfoXML)"

    // Convert ActivationInfoXML to Data
    guard let ActivationInfoXMLData = ActivationInfoXML.data(using: .utf8) else {
        fatalError("Failed to encode ActivationInfoXML")
    }

    // Sign the ActivationInfoXMLData
    var error: Unmanaged<CFError>?
    guard let signature = SecKeyCreateSignature(privateKey, .rsaSignatureMessagePKCS1v15SHA1, ActivationInfoXMLData as CFData, &error) as Data? else {
        fatalError("Failed to create signature: \(error?.takeUnretainedValue().localizedDescription ?? "Unknown error")")
    }

    // Convert signature to base64
    let ActivationInfoXMLSignature = signature.base64EncodedString()

    print("Created ActivationInfoXMLSignature = \(ActivationInfoXMLSignature)")
    
    
    //creatung FairPlayCertChain
    //Using our FairPlayCertChain
    let FairPlayCertCain = """
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
"""
    //Creating ActivationXML
    //we are using our ActivationXML for ByPass...
    let ActivationXML = """
<plist version=\"1.0\">
<dict>
    <key>ActivationRandomness</key>
    <string>KavishaAct</string>
    <key>ActivationRequiresActivationTicket</key>
    <true/>
    <key>ActivationState</key>
    <string>Unactivated</string>
    <key>BasebandActivationTicketVersion</key>
    <string>V2</string>
    <key>BasebandChipID</key>
    <integer>7278817</integer>
    <key>BasebandMasterKeyHash</key>
    <string>8CB15EE4C8002199070D9500BB8FB183B02713A5CA2A6B92DB5E75CE15536182</string>
    <key>BasebandSerialNumber</key>
    <data>
    0xEMaVABEqT5emWk
    </data>
    <key>BuildVersion</key>
    <string>\(BuildVersion)</string>
    <key>DeviceCertRequest</key>
    <data>
    LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0NCk1JSUN6akNDQWJZ
    Q0FRQXdiVEVMTUFrR0ExVUVCaE1DUTBFeEV6QVJCZ05WQkFnTUNrTmhiR2xtYjNK
    dWFXRXgNCkVqQVFCZ05WQkFjTUNVTjFjR1Z5ZEdsdWJ6RVVNQklHQTFVRUNnd0xR
    WEJ3YkdVc0lFbHVZeTR4RGpBTUJnTlYNCkJBc01CVUZ3Y0d4bE1ROHdEUVlEVlFR
    RERBWnBVR2h2Ym1Vd2dnRWlNQTBHQ1NxR1NJYjNEUUVCQVFVQUE0SUINCkR3QXdn
    Z0VLQW9JQkFRQ3dqeWxYQ0pQZU00ZWh5RXZoZjBTNFp2U2tXVW01Q3ZqS1VpWTFU
    WWZpNlJiYmtxTngNCm5XcHVwcmw3L2dJUVRwOHdlTENzb0JpNHZ3NEtOUjdGM2Q2
    QksvdTlDMjlkOStndWtCSjVkMXY2SmFvYUNPUnANCmdLcE8rcm80OWJoakFhYWFj
    anpRaWY0TW5GOHozdk9mS2tDQStweXNIQkE0VS83WUxkTWlxWFhYb2lkUW1wVDUN
    ClFDRExETy9pb21JODFzWXQ5eVQ3dGhSR21NL3pOSWR6S1Z0dTFiTzB0SVg0OVhh
    UFUzbkZrbjgxeFd0bnU0U3oNClFNTUpZL2NlWkVCSEVFbkt5TDRxUEhERHdzeUxE
    RDFCR0FhR0RVaGR4VEZaS2MySmovY0I0akcxaDNVTis0Y0QNCmxvakYwRThLcVdu
    OGZ4Nlp0WkNBeVNaZWVoNWRuVE90QWlkakFnTUJBQUdnSERBYUJna3Foa2lHOXcw
    QkNRSXgNCkRRd0xSVmd6WTNWMGFXOU9NMUl3RFFZSktvWklodmNOQVFFTEJRQURn
    Z0VCQUtNalNSUzFCUDNFWjlRaVZQUW4NCkJYcDBmY3I4djd6N2pQQ2Vxb3pkY0Vh
    ZHZncVRkTWVaTHBQMWFEU2FMOG14bXBEaFlqNm1PL2dheWMzaGxPWDQNCnNnRnhw
    RE8vblliWExFbGNGc2pEMnR1ajk2cVYydmM1enVpU3QwOHJxa1lWTTA4ZTJjUlJ3
    cjhMK2RPRjVvbVINCkNsTE5HSFJrakZXcThPTm94WDdxYzN3MWljYURqZ292Q0NC
    a2NUN3R5TlhXdVY3amZ2TDkwMG5qcEdUWFprdWwNClV4Y01QczdkSjY4YlFRK2hs
    azNmeDFLd0ZNZG1ZYkZTT051RGRsdGJPNlZ0Qyt1Z0YxbGRHbkhmeUxHdjNqMy8N
    Cmp4S0hJSVNwa2lzeVV5RmJHMVdNV3hJRG5JSkZGMXJmVzQ5MUMyYVNWQmNIZ0tH
    bnJ1SGo0NHZyT1haeUt0bGgNCm1Icz0NCi0tLS0tRU5EIENFUlRJRklDQVRFIFJF
    UVVFU1QtLS0tLQ0K
    </data>
    <key>DeviceClass</key>
    <string>\(Variant)"</string>
    <key>DeviceVariant</key>
    <string>A</string>
    <key>FMiPAccountExists</key>
    <false/>
    <key>InternationalMobileEquipmentIdentity</key>
    <string>013423005288880</string>
    <key>ModelNumber</key>
    <string>\(ModelNumber)</string>
    <key>ProductType</key>
    <string>\(ProductType)</string>
    <key>ProductVersion</key>
    <string>\(iOS)</string>
    <key>RegionCode</key>
    <string>LZ</string>
    <key>RegionInfo</key>
    <string>LZ/A</string>
    <key>SIMStatus</key>
    <string>kCTSIMSupportSIMStatusNotInserted</string>
    <key>SupportsPostponement</key>
    <true/>
    <key>kCTPostponementInfoServiceProvisioningState</key>
    <true/>
    <key>SerialNumber</key>
    <string>C38K4AG6DTTN</string>
    <key>SupportsPostponement</key>
    <true/>
    <key>UniqueChipID</key>
    <integer>\(UniqueChipID)</integer>
    <key>UniqueDeviceID</key>
    <string>\(UniqueDeviceID)</string>
</dict>
</plist>
"""
}

#Preview {
    ContentView()
}



