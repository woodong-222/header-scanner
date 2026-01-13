#pragma once

#include "../../../sutra/Src/_SutraFramework/Struct.h"

class CHeaderScanner
{
public:
	CHeaderScanner(void);
	~CHeaderScanner(void);

	ECODE Scan(std::tstring strURL);
};
