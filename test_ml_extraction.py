from extract import ThreatExtractor

def main():
    print("Initializing ThreatExtractor...")
    extractor = ThreatExtractor()
    
    test_urls = [
        "https://google.com",
        "https://github.com/microsoft",
        "http://verification-login-paypal.com/secure/login.php",
        "http://192.168.1.1/admin.php",
        "http://malicious-phishing-site.ru/download.exe"
    ]
    
    print("\n[+] Testing ML Model Predictions directly:")
    for url in test_urls:
        prob = extractor.ml_predict_ioc(url, "url")
        print(f"URL: {url}")
        print(f"  Malicious Probability: {prob:.4f}\n")
        
    print("[+] Testing full extraction pipeline via extract.py (which uses regex + ML + LLM validation if available):")
    sample_text = "Users reported clicking on http://verification-login-paypal.com/secure/login.php and downloading malware."
    result = extractor.extract_all(sample_text)
    
    print("Parsed IOCs:")
    for ioc in result.get('iocs', []):
        print(f"  Value: {ioc['value']}, Type: {ioc['type']}, Extraction Method: {ioc.get('extraction_method', 'N/A')}, Confidence: {ioc.get('confidence', -1)}, ML Confidence: {ioc.get('ml_confidence', -1)}")

if __name__ == "__main__":
    main()
