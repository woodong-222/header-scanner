#pragma once

#include <unordered_map>
#include "../../../sutra/Src/_SutraFramework/Struct.h"

class CSurfaceScanner
{
public:
	CSurfaceScanner(void);
	~CSurfaceScanner(void);

	ECODE Scan(std::tstring strURL);
};

