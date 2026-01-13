#include "pch.h"
#include "SurfaceScanner.h"
#include "HelperFunc.h"
#include "SurfaceScannerHelper.h"

CSurfaceScanner::CSurfaceScanner(void)
{
}

CSurfaceScanner::~CSurfaceScanner(void)
{
}

ECODE CSurfaceScanner::Scan(std::tstring strURL)
{
	ECODE nRet = EC_SUCCESS;

	std::map<std::tstring, std::tstring> mapDetectParam;
	mapDetectParam[TEXT("url")] = strURL;

	try
	{
		UrlData stUrlData;
		nRet = ParseURL(strURL, stUrlData);
		if (EC_SUCCESS != nRet)
			throw exception_format(TEXT("ParseURL(%s) failure, %d"), strURL.c_str(), nRet);

		//// -------------------- Code 1: IP Address Host Scan -------------------- //
		//if (ares_wrapper::IsIpAddress(stUrlInfo.strHost))
		//	SutraLog()->AddEvent(2, TEXT("IpAddress"), { {TEXT("ip"), stUrlInfo.strHost} });

		//// -------------------- Code 2: Phishing Pattern Scan -------------------- //
		//std::tstring brand = PhishingPatternScan(stUrlData.fqdn, stUrlData.path, stUrlData.query, stUrlData.domain_name);
		//if (!brand.empty())
		//	SutraLog()->AddEvent(4, TEXT("PhishingSuspected"), { {TEXT("brand"), brand} });

		// -------------------- Code 3: User Page Scan -------------------- //
		std::tstring strUserPageContext = UserPageScan(stUrlData);
		if (!strUserPageContext.empty())
			mapDetectParam[TEXT("userpage-context")] = strUserPageContext;

		// -------------------- Code 4: TLD Scan -------------------- //
		std::tstring suspicious_tld = TldScan(stUrlData);
		if (!suspicious_tld.empty())
			mapDetectParam[TEXT("suspicious-tld")] = suspicious_tld;

		// -------------------- Code 5: Executable File Scan -------------------- //
		std::tstring strExeFileName = ExecutableFileScan(stUrlData);
		if (!strExeFileName.empty())
			mapDetectParam[TEXT("executable-file")] = strExeFileName;

		// -------------------- Code 6: Short URL Scan -------------------- //
		std::tstring strShortURL = ShortUrlScan(stUrlData);
		if (!strShortURL.empty())
			mapDetectParam[TEXT("short-url")] = strShortURL;

		// -------------------- Code 7: DGA Scan -------------------- //
		std::tstring strCDNProvider = CdnDomainScan(stUrlData); // CDN은 엔트로피가 높아서 제외
		if (strCDNProvider.empty())
		{
			double dga_score = DgaScan(stUrlData);
			if (dga_score)
				mapDetectParam[TEXT("dga-score")] = StringFrom(dga_score);
		}
		// -------------------- Code 12: CDN Domain Scan -------------------- //
		if (!strCDNProvider.empty())
			mapDetectParam[TEXT("provider")] = strCDNProvider;

		//// -------------------- Code 8: Keyword Scan -------------------- //
		//std::vector<std::tstring> vecKeywords = KeywordScan(stUrlData.path, stUrlData.query);
		//std::tstring strKeyword = JoinStrings(vecKeywords);
		//if (!strKeyword.empty())
		//	SutraLog()->AddEvent(4, TEXT("PhishingSuspected"), { {TEXT("keywords"), strKeyword } });

		//// -------------------- Code 9: Long URL Scan -------------------- //
		//std::tstring url_length = LongUrlScan(stUrlData.normalized_url);
		//if (!url_length.empty())
		//	SutraLog()->AddEvent(1, TEXT("LongUri"), { {TEXT("length"), StringFrom((QWORD)strURL.length())}});

		//// -------------------- Code 10: Vulnerability Pattern Scan -------------------- //
		//std::vector<std::tstring> vecVulPatterns = VulnerabilityPatternScan(stUrlData.query);
		//std::tstring strVulPatterns = JoinStrings(vecVulPatterns);
		//if (!strVulPatterns.empty())
		//	SutraLog()->AddEvent(3, TEXT("VulnerablePattern"), { {TEXT("pattern"), strVulPatterns} });

		//// -------------------- Code 11: Base64 Scan -------------------- //
		//std::vector<std::pair<std::tstring, std::tstring>> b64_pairs = Base64Scan(stUrlData.path, stUrlData.query);
		//if (!b64_pairs.empty())
		//{
		//	std::vector<std::tstring> encoded_list, decoded_list;
		//	for (auto iter : b64_pairs) {
		//		encoded_list.push_back(iter.first);
		//		decoded_list.push_back(iter.second);
		//	}
		//	std::tstring strEncodedStrings = JoinStrings(encoded_list);
		//	std::tstring strDecodedStrings = JoinStrings(decoded_list);
		//	SutraLog()->AddEvent(3, TEXT("Base64Url"), { {TEXT("encoded-strings"), strEncodedStrings}, {TEXT("decoded-strings"), strDecodedStrings} });
		//}

		//// -------------------- Code 13: Credential Exposure Scan -------------------- //
		//std::pair<std::tstring, std::tstring> credentials = CredentialExposureScan(stUrlData.normalized_url);
		//if (!credentials.first.empty())
		//	SutraLog()->AddEvent(4, TEXT("CredentialExposed"), { {TEXT("user"), credentials.first}, {TEXT("password"), credentials.second} });

		// -------------------- Code 14: Sensitive Token Scan -------------------- //
		if (SensitiveTokenScan(stUrlData.mapQueryParam))
			mapDetectParam[TEXT("sensitive-token")] = stUrlData.strQuery;

		//// -------------------- Code 15: Unusual Scheme Scan -------------------- //
		//std::tstring unusual_scheme = UnusualSchemeScan(stUrlData.scheme, stUrlData.normalized_url);
		//if (!unusual_scheme.empty())
		//	SutraLog()->AddEvent(4, TEXT("UnusualScheme"), {
		//		{TEXT("scheme"), unusual_scheme},
		//		});

		//// -------------------- Code 16: Dangerous Parameter Scan -------------------- //
		//std::vector<std::tuple<std::tstring, std::tstring, double>> dangerous_params = DangerousParameterScan(query_params, stUrlData.fqdn);
		//if (!dangerous_params.empty())
		//{
		//	std::tstring strKey, strValue, strEntropy;
		//	for (const auto& [key, value, entropy] : dangerous_params)
		//	{
		//		strKey += key + TEXT(", ");
		//		strValue += value + TEXT(", ");
		//		strEntropy += std::to_string(entropy) + TEXT(", ");
		//	}
		//	SutraLog()->AddEvent(3, TEXT("DangerousParam"), {
		//		{TEXT("key"), strKey},
		//		{TEXT("value"), strValue},
		//		{TEXT("entropy"), strEntropy},
		//		});
		//}

		// -------------------- Code 17: Punycode/Homograph Scan -------------------- //
		if (PunycodeHomographScan(stUrlData.strFqdn))
			mapDetectParam[TEXT("homograph")] = stUrlData.strFqdn;

		// -------------------- Code 18: Non-Standard Port Scan -------------------- //
		// 오탐여지가 많아서 제외

		// -------------------- Code 19: Typosquatting Detection -------------------- //
		std::tstring strTypoKeyword = MatchTyposquatting(stUrlData);
		if (!strTypoKeyword.empty())
			mapDetectParam[TEXT("typosquatting")] = strTypoKeyword;

		// -------------------- Code 20: Double Extension Detection -------------------- //
		std::tstring strDoubleExt = DoubleExtensionScan(stUrlData);
		if (!strDoubleExt.empty())
			mapDetectParam[TEXT("double-ext")] = strDoubleExt;

		// -------------------- Code 21: Open Redirect Detection -------------------- //
		std::tstring strRedirect = OpenRedirectScan(stUrlData);
		if (!strRedirect.empty())
			mapDetectParam[TEXT("redirect-target")] = strRedirect;

		// -------------------- Code 22: Suspicious URL Structure Detection -------------------- //
		if (SuspiciousUrlStructureScan(stUrlData.strFqdn))
			mapDetectParam[TEXT("suspicious-url-structure")] = stUrlData.strFqdn;

		if (ScanAuthorityAbuse(stUrlData))
			mapDetectParam[TEXT("authority-abuse")] = stUrlData.strQuery;

		Evaluate(mapDetectParam);
	}
	catch (const std::exception& e)
	{
		Log_Error("%s", e.what());
		Evaluate(mapDetectParam);
		return nRet;
	}

	return EC_SUCCESS;
}
