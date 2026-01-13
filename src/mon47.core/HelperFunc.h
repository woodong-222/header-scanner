#pragma once

#include "Struct.h"

std::tstring JoinStrings(const std::vector<std::tstring>& vecValues, std::tstring strDelimiter = TEXT(", "), size_t tStartPos = 0);

bool IsBase64(const std::tstring& str);
std::tstring DecodeBase64Helper(std::tstring strContext);

std::tstring NormalizeURL(ST_URL_DATA* pUrlData);
ECODE ParseURL(std::tstring strUrl, UrlData& outInfo);

double CalculateHexDensity(const std::tstring& label);
double CalculateEntropy(const std::tstring& str);

void Evaluate(std::map<std::tstring, std::tstring>& mapDetectParam);