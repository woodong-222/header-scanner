#pragma once

#include <string>
#include <vector>
#include <map>
//
//struct QueryParamValue
//{
//	std::string key;		// 검색용
//	std::string value;		// 원본
//};
//using QueryParamMap = std::unordered_multimap<std::string, QueryParamValue>;

struct ST_URL_DATA
{
	std::tstring strScheme;
	std::tstring strFqdn;
	std::tstring strPort;
	std::tstring strPath;	// /를 제외한 경로 정보
	std::tstring strQuery;
	std::map<std::tstring, std::tstring> mapQueryParam;
	std::tstring strHost;
	std::tstring strHostName;
	std::tstring strDomain;
	std::tstring strDomainName;
	std::tstring strTLD;
	std::tstring strTLD2;
	std::tstring strUserInfo;
	std::tstring strFragment;
	WORD wPort;
};

struct UrlData : public ST_URL_DATA
{
	std::tstring strNormalizedURL;
};

struct CertInfo
{
	std::string subject;
	std::string issuer;
	std::string serial_number;
	std::string common_name;
	std::string signature_algorithm;
	int key_size;
	std::string not_before;
	std::string not_after;
	int days_until_expiry;
	bool is_self_signed;
	bool is_expired;
	bool has_ct_scts;
	std::vector<std::string> san_list;
	long ssl_verify_result;
	int chain_length;
	std::string tls_version;
	std::string cipher_suite;
	bool is_ca;
	int path_length;
	bool ku_digital_signature;
	bool ku_key_encipherment;
	bool ku_key_cert_sign;
	bool eku_server_auth;
	bool eku_client_auth;
	std::string ocsp_url;
	std::string ca_issuer_url;
	std::vector<std::string> crl_urls;
	std::vector<uint8_t> ocsp_response_raw;
	bool has_ocsp_stapling;
	bool ocsp_stapling_revoked;
	std::string ocsp_stapling_response_status;
	bool hostname_verified;
	std::string target_hostname;
	std::string initial_url;
	std::string final_url;
	std::string final_hostname;
	bool was_redirected;
	bool final_hostname_verified;
	int redirect_count;
	bool connection_failed;
	std::string connection_error;
	bool has_no_cert;
	bool has_downgrade;
	bool has_weak_key;
	bool has_weak_signature;
	bool is_fresh_cert;
	bool has_san_ip_address;
	int days_since_issue;
	bool chain_has_weak_signatures;
	bool chain_has_weak_keys;
	bool chain_has_path_length_violation;
	bool chain_has_key_usage_violation;
	bool chain_has_expired_ca;
	std::vector<std::string> chain_validation_errors;
	int verify_result;

	CertInfo()
		: key_size(0)
		, days_until_expiry(0)
		, is_self_signed(false)
		, is_expired(false)
		, has_ct_scts(false)
		, ssl_verify_result(0)
		, chain_length(0)
		, is_ca(false)
		, path_length(-1)
		, ku_digital_signature(false)
		, ku_key_encipherment(false)
		, ku_key_cert_sign(false)
		, eku_server_auth(false)
		, eku_client_auth(false)
		, hostname_verified(false)
		, was_redirected(false)
		, final_hostname_verified(false)
		, redirect_count(0)
		, connection_failed(false)
		, has_no_cert(false)
		, has_downgrade(false)
		, has_weak_key(false)
		, has_weak_signature(false)
		, is_fresh_cert(false)
		, has_san_ip_address(false)
		, days_since_issue(0)
		, chain_has_weak_signatures(false)
		, chain_has_weak_keys(false)
		, chain_has_path_length_violation(false)
		, chain_has_key_usage_violation(false)
		, chain_has_expired_ca(false)
		, verify_result(0)
		, has_ocsp_stapling(false)
		, ocsp_stapling_revoked(false)
	{
	}
};

struct CertCaptureContext
{
	std::vector<CertInfo> captured_certs;
	std::string hostname;
	std::string initial_url;
	std::string final_url;
	bool captured;
};

struct HttpHeader
{
	std::map<std::string, std::string> headers;
	std::string raw_headers;
	int status_code;
};

struct RedirectInfo
{
	std::string url;
	int status_code;
};

struct FetchResult
{
	int http_response_code;
	std::string initial_url;
	std::string final_url;
	std::string html_content;
	HttpHeader http_header;
	std::vector<CertInfo> cert_chain;
	std::vector<RedirectInfo> redirect_history;
};

struct RdapIpData
{
	std::string ip;
	std::string country;
	std::string name;
	int age_days;
	std::vector<std::string> statuses;
	bool has_abuse_contact;
	std::string handle;
	std::vector<std::string> cidrs;
	int abuse_contact_type;
	std::string abuse_contact_detail;
};

struct WhoisData
{
	std::string domain;
	std::string registrar;
	std::string creation_date;
	std::string expiration_date;
	std::string name_servers;
};

struct DnsARecord
{
	std::string ip_address;
	int ttl;
};

struct DnsMXRecord
{
	std::string exchange;
	int priority;
	int ttl;
};

struct DnsNSRecord
{
	std::string nameserver;
	int ttl;
};

struct DnsSecInfo
{
	bool available;
	bool authenticated;
};

struct RdapDomainData
{
	std::string name;
	int age_days;
	int expiry_days;
	int registration_period_days;
	int update_days_ago;
	std::vector<std::string> statuses;
	bool has_abuse_contact;
	std::string registrar;
	std::vector<std::string> nameservers;
	std::string country;
	bool uses_privacy_service;
	int abuse_contact_type;
	std::string abuse_contact_detail;
};

struct CymruData
{
	bool is_valid;
	std::string as_number;
	std::string country_code;
	std::string as_name;
	std::string allocated_date;
};

struct GetterData
{
	int http_response_code;
	std::string final_url; // 최종 리다이렉트 url
	std::string original_url; // 최초 요청한 url
	std::string strNormalizedURL; // 정규화된 url
	std::string display_url; // 보여지는 url
	std::string strFqdn; // 정규화된 호스트 이름
	std::string final_fqdn;
	std::vector<std::string> ip_addresses;

	bool is_server_alive;

	RdapIpData rdap_ip_data;
	std::vector<WhoisData> whois_data;

	std::vector<DnsARecord> dns_a_records;
	std::vector<DnsMXRecord> dns_mx_records;
	std::vector<DnsNSRecord> dns_ns_records;
	DnsSecInfo dns_sec_info;

	RdapDomainData rdap_domain_data;
	CymruData cymru_data;
	std::vector<CymruData> all_cymru_data;

	bool is_subdomain = false;
	std::string root_domain;
	std::vector<DnsARecord> root_dns_a_records;
	CymruData root_cymru_data;

	HttpHeader http_header;
	std::vector<CertInfo> cert_chain;
	std::vector<RedirectInfo> redirect_history;

	std::string html_content;
	std::string html_file_path;
	std::vector<std::string> js_file_paths;

	bool skip_scanner;
	std::string skip_reason;

	GetterData()
		: http_response_code(0),
		is_server_alive(false),
		is_subdomain(false),
		skip_scanner(false)
	{
	}
};
