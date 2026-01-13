#pragma once

bool MatchesOfficialDomain(const std::tstring& strOfficialDomain, const std::tstring& strLowerDomainName, const std::tstring& strLowerFqdn);
bool IsPronounceable(const std::tstring& strDomainName);
double CalculateSyntaxDensity(const std::tstring& value);
bool IsNumericParameterKey(const std::tstring& key);
bool IsNumericValue(const std::tstring& value);
std::tstring GetRegistrableDomain(std::tstring strDomain, std::tstring strSuffix);
double GetKeyDistance(char a, char b);
double WeightedKeyboardDistance(const std::tstring& s1, const std::tstring& s2);

//std::tstring IpAddressHostScan(const std::tstring& host_name);
//std::tstring PhishingPatternScan(const std::tstring& fqdn, const std::tstring& path, const std::tstring& query, const std::tstring& domain_name);
std::tstring UserPageScan(const ST_URL_DATA& UrlData);
std::tstring TldScan(const ST_URL_DATA& UrlData);
std::tstring ExecutableFileScan(const ST_URL_DATA& UrlData);
std::tstring ShortUrlScan(const ST_URL_DATA& UrlData);
std::tstring CdnDomainScan(const ST_URL_DATA& UrlData);
double DgaScan(const ST_URL_DATA& UrlData);
//std::vector<std::tstring> KeywordScan(const std::tstring& path, const std::tstring& query);
//std::tstring LongUrlScan(const std::tstring& url);;
//std::vector<std::tstring> VulnerabilityPatternScan(const std::tstring& query);;
//std::vector<std::pair<std::tstring, std::tstring>> Base64Scan(const std::tstring& path, const std::tstring& query);
//std::pair<std::tstring, std::tstring> CredentialExposureScan(const std::tstring& normalized_url);
//std::vector<std::tuple<std::tstring, std::tstring, double>> SensitiveTokenScan(const QueryParamMap& params);
//std::tstring UnusualSchemeScan(const std::tstring& scheme, const std::tstring& normalized_url);
//std::vector<std::tuple<std::tstring, std::tstring, double>> DangerousParameterScan(const QueryParamMap& params, const std::tstring& current_fqdn);
//std::tuple<int, std::tstring, bool> NonStandardPortScan(const std::tstring& scheme, const std::tstring& port);
std::tstring OpenRedirectScan(const ST_URL_DATA& UrlData);
std::tstring DoubleExtensionScan(const ST_URL_DATA& UrlData);
bool SuspiciousUrlStructureScan(std::tstring strFqdn);
bool ScanAbnormalUrlChar(std::tstring strOriginalUrl);
bool ScanAuthorityAbuse(const ST_URL_DATA& UrlData);
bool PunycodeHomographScan(const std::tstring& strFqdn);
bool SensitiveTokenScan(const std::map<std::tstring, std::tstring>& mapParam);

std::tstring NormalizeForTyposquatting(std::tstring strToken);
std::tstring MatchTyposquatting(const UrlData& UrlData);